// Package gate is DRS's protocol enforcement point. An Adapter translates one
// wire protocol (plain HTTP JSON, MCP, A2A) into a Call; Decide verifies the
// chain, the command, the body binding and the replay nonce — in that order —
// and returns a Decision. The verifier core never learns protocol details.
package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/binding"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/metrics"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
)

// BundleHeader is the HTTP header that carries a base64url-encoded bundle.
const BundleHeader = "X-DRS-Bundle"

// BundleMetaKey is the namespaced key carrying the bundle inside a JSON-RPC
// message (MCP params._meta, A2A params.metadata).
const BundleMetaKey = "xyz.okeyamy.drs/bundle"

// MaxBodyBytes caps a gated request body (64 KiB, hard-coded by design).
const MaxBodyBytes = 64 * 1024

// maxBundleBytes caps the encoded bundle before decoding (decoded ≤ 65,535 B).
const maxBundleBytes = 87_381

// Inbound is one protocol request as seen by an enforcement point.
type Inbound struct {
	Method string
	Header http.Header
	Body   []byte
}

// Call is what an adapter extracted from a request that must be gated.
type Call struct {
	Bundle string          // base64url-encoded chain bundle
	Cmd    string          // exact invocation.cmd required; "" accepts any
	Args   []byte          // JSON the signed invocation.args must equal
	ID     json.RawMessage // JSON-RPC request id, nil for plain HTTP
}

// Denial describes why a request was refused.
type Denial struct {
	Status     int
	Code       string
	Detail     string
	Suggestion string
}

func (d *Denial) Error() string { return d.Code + ": " + d.Detail }

func deny(status int, code, detail, suggestion string) *Denial {
	return &Denial{Status: status, Code: code, Detail: detail, Suggestion: suggestion}
}

// Adapter translates one wire protocol.
type Adapter interface {
	Name() string
	// Extract returns gated=false for requests that carry no tool action
	// (handshakes, discovery, notifications, stream GETs). A non-nil error is
	// always a *Denial.
	Extract(in Inbound) (call Call, gated bool, err error)
	// Reject renders a denial in the protocol's native error format.
	Reject(id json.RawMessage, d *Denial) (status int, body []byte)
}

// Config is what Decide needs. Build it with NewConfig.
type Config struct {
	deps    verify.Deps
	nonces  nonce.Checker
	binding binding.Mode
}

// NewConfig validates and returns a gate configuration. Replay protection is
// mandatory: a nil nonce checker is an error, not a silently open gate.
func NewConfig(deps verify.Deps, nonces nonce.Checker, mode binding.Mode) (Config, error) {
	if nonces == nil {
		return Config{}, errors.New("gate: nonce checker is required")
	}
	parsed, err := binding.ParseMode(string(mode))
	if err != nil {
		return Config{}, fmt.Errorf("gate: %w", err)
	}
	return Config{deps: deps, nonces: nonces, binding: parsed}, nil
}

// Decision is the outcome for one request.
type Decision struct {
	Allow   bool                       `json:"allow"`
	Gated   bool                       `json:"gated"`
	Status  int                        `json:"status"`
	Body    json.RawMessage            `json:"response,omitempty"`
	Context *types.VerificationContext `json:"context,omitempty"`
}

// Decide runs the full enforcement pipeline for one request.
func Decide(ctx context.Context, cfg Config, a Adapter, in Inbound) Decision {
	call, gated, err := a.Extract(in)
	if err != nil {
		return refuse(a, call.ID, asDenial(err), gated)
	}
	if !gated {
		return Decision{Allow: true, Status: http.StatusOK}
	}
	vctx, d := enforce(ctx, cfg, call)
	if d != nil {
		return refuse(a, call.ID, d, true)
	}
	return Decision{Allow: true, Gated: true, Status: http.StatusOK, Context: vctx}
}

func enforce(ctx context.Context, cfg Config, call Call) (*types.VerificationContext, *Denial) {
	if call.Bundle == "" {
		return nil, deny(http.StatusUnauthorized, "MISSING_BUNDLE",
			"no DRS bundle on a gated request",
			"Attach a base64url DRS bundle in the X-DRS-Bundle header or the "+BundleMetaKey+" metadata key.")
	}
	bundle, err := decodeBundle(call.Bundle)
	if err != nil {
		return nil, deny(http.StatusBadRequest, "MALFORMED_BUNDLE", err.Error(),
			"Encode the bundle as base64url(JSON.stringify(bundle)).")
	}
	result := verify.Chain(ctx, bundle, cfg.deps)
	if !result.Valid {
		code, msg, hint := "VERIFICATION_FAILED", "chain did not verify", ""
		if result.Error != nil {
			code, msg, hint = result.Error.Code, result.Error.Message, result.Error.Suggestion
		}
		return nil, deny(http.StatusForbidden, code, msg, hint)
	}
	inv, err := decodeInvocation(bundle.Invocation)
	if err != nil {
		return nil, deny(http.StatusBadRequest, "MALFORMED_INVOCATION", err.Error(), "")
	}
	if call.Cmd != "" && inv.Cmd != call.Cmd {
		return nil, deny(http.StatusForbidden, "CMD_MISMATCH",
			fmt.Sprintf("invocation.cmd %q does not authorise %q", inv.Cmd, call.Cmd),
			"Sign the invocation with cmd "+call.Cmd+".")
	}
	if d := checkBinding(cfg.binding, call.Args, inv.Args); d != nil {
		return nil, d
	}
	if d := commitNonce(cfg.nonces, inv.Jti); d != nil {
		return nil, d
	}
	return result.Context, nil
}

func checkBinding(mode binding.Mode, body, signed []byte) *Denial {
	if mode == binding.ModeOff {
		metrics.BindingChecks.WithLabelValues("off").Inc()
		return nil
	}
	if err := binding.CheckRaw(body, signed); err != nil {
		if mode == binding.ModeLenient {
			metrics.BindingChecks.WithLabelValues("mismatch_lenient").Inc()
			slog.Warn("binding mismatch (lenient — passing through)", "error", err)
			return nil
		}
		metrics.BindingChecks.WithLabelValues("mismatch_enforced").Inc()
		return deny(http.StatusForbidden, "BINDING_MISMATCH", err.Error(),
			"The executed arguments must equal the signed invocation.args.")
	}
	metrics.BindingChecks.WithLabelValues("match").Inc()
	return nil
}

func commitNonce(ns nonce.Checker, jti string) *Denial {
	if jti == "" {
		return deny(http.StatusBadRequest, "MISSING_JTI", "invocation has no jti", "Issue invocations with a unique jti.")
	}
	if err := ns.Check(jti); err != nil {
		if errors.Is(err, nonce.ErrReplayDetected) {
			metrics.NonceChecks.WithLabelValues("replay").Inc()
			return deny(http.StatusConflict, "REPLAY_DETECTED", "invocation jti already consumed",
				"Sign a new invocation with a unique jti.")
		}
		metrics.NonceChecks.WithLabelValues("exhausted").Inc()
		return deny(http.StatusServiceUnavailable, "NONCE_STORE_UNAVAILABLE", "nonce store unavailable",
			"Retry shortly.")
	}
	metrics.NonceChecks.WithLabelValues("accepted").Inc()
	return nil
}

func refuse(a Adapter, id json.RawMessage, d *Denial, gated bool) Decision {
	status, body := a.Reject(id, d)
	return Decision{Allow: false, Gated: gated, Status: status, Body: body}
}

func asDenial(err error) *Denial {
	var d *Denial
	if errors.As(err, &d) {
		return d
	}
	return deny(http.StatusBadRequest, "BAD_REQUEST", err.Error(), "")
}

func decodeBundle(encoded string) (types.ChainBundle, error) {
	if len(encoded) > maxBundleBytes {
		return types.ChainBundle{}, errors.New("bundle exceeds maximum size")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return types.ChainBundle{}, errors.New("bundle is not valid base64url")
	}
	var b types.ChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return types.ChainBundle{}, errors.New("bundle is not valid JSON")
	}
	return b, nil
}

type invocationClaims struct {
	Cmd  string          `json:"cmd"`
	Jti  string          `json:"jti"`
	Args json.RawMessage `json:"args"`
}

// decodeInvocation reads the claims of an invocation JWT that verify.Chain
// has already authenticated. Args stay raw so large integers keep precision.
func decodeInvocation(jwt string) (invocationClaims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return invocationClaims{}, errors.New("invocation is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invocationClaims{}, errors.New("invocation payload is not base64url")
	}
	var c invocationClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return invocationClaims{}, errors.New("invocation payload is not JSON")
	}
	return c, nil
}

// SignedArgs returns the raw invocation.args of an invocation JWT. Call it
// only after verify.Chain has authenticated the JWT.
func SignedArgs(invocationJWT string) ([]byte, error) {
	c, err := decodeInvocation(invocationJWT)
	if err != nil {
		return nil, err
	}
	return c.Args, nil
}
