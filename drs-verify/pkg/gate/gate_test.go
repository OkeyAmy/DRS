package gate_test

// Every request below is either a wire envelope recorded from an official SDK
// (testdata/wire, captured 2026-10-01 from @modelcontextprotocol/client 2.2.0
// and @a2a-js/sdk 1.3.0) or derived from one. Every bundle is a real
// Ed25519-signed chain from testkit, verified by the production verifier.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/binding"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/gate"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
	"github.com/OkeyAmy/DRS/drs-verify/testkit"
)

const toolServer = "did:web:tools.example"

type wire struct {
	HTTPMethod string                 `json:"http_method"`
	Headers    map[string]string      `json:"headers"`
	Body       map[string]interface{} `json:"body"`
}

func loadWire(t *testing.T, name string) wire {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w wire) inbound(t *testing.T) gate.Inbound {
	t.Helper()
	h := http.Header{}
	for k, v := range w.Headers {
		h.Set(k, v)
	}
	var body []byte
	if w.Body != nil {
		var err error
		if body, err = json.Marshal(w.Body); err != nil {
			t.Fatal(err)
		}
	}
	return gate.Inbound{Method: w.HTTPMethod, Header: h, Body: body}
}

func newConfig(t *testing.T, mode binding.Mode) gate.Config {
	t.Helper()
	deps, err := verify.NewDefaultDeps(toolServer)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gate.NewConfig(deps, nonce.New(1000, time.Hour), mode)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newIssuer(t *testing.T, cmd string, policy types.Policy) *testkit.Issuer {
	t.Helper()
	iss, err := testkit.NewIssuer(toolServer, cmd, policy)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func sign(t *testing.T, iss *testkit.Issuer, cmd string, args map[string]interface{}) string {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	h, err := iss.Header(cmd, raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// mcpToolCall loads a recorded tools/call and returns it with its arguments
// and tool name, ready to sign. Signed args are params.arguments plus
// {"tool": params.name}. blindfold: contract — the MCP binding mapping in
// pkg/gate/adapters.go doc comment and docs/specs protocol-adapters spec.
func mcpToolCall(t *testing.T, name string) (wire, string, map[string]interface{}) {
	t.Helper()
	w := loadWire(t, name)
	params := w.Body["params"].(map[string]interface{})
	args := map[string]interface{}{}
	for k, v := range params["arguments"].(map[string]interface{}) {
		args[k] = v
	}
	args["tool"] = params["name"]
	return w, params["name"].(string), args
}

func withHeaderBundle(w wire, bundle string) wire {
	h := map[string]string{gate.BundleHeader: bundle}
	for k, v := range w.Headers {
		h[k] = v
	}
	w.Headers = h
	return w
}

func withMetaBundle(t *testing.T, w wire, bundle string) wire {
	t.Helper()
	raw, _ := json.Marshal(w.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	params := body["params"].(map[string]interface{})
	meta, _ := params["_meta"].(map[string]interface{})
	if meta == nil {
		meta = map[string]interface{}{}
	}
	meta[gate.BundleMetaKey] = bundle
	params["_meta"] = meta
	w.Body = body
	return w
}

func bundleHeader(b string) http.Header {
	h := http.Header{}
	h.Set(gate.BundleHeader, b)
	return h
}

func rpcErrorCode(t *testing.T, d gate.Decision) string {
	t.Helper()
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Data struct {
				Code string `json:"code"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(d.Body, &resp); err != nil {
		t.Fatalf("denial body is not JSON-RPC: %s", d.Body)
	}
	return resp.Error.Data.Code
}

// ── MCP: pass-through of everything that is not a tool action ──────────────

func TestMCPPassesHandshakeAndStreamTraffic(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	for _, name := range []string{
		"mcp_2025-11-25_initialize_post_na",
		"mcp_2025-11-25_notifications-initialized_post_na",
		"mcp_2025-11-25_GET_get_na",
		"mcp_2026-07-28_server-discover_post_na",
	} {
		d := gate.Decide(context.Background(), cfg, gate.MCP{}, loadWire(t, name).inbound(t))
		if !d.Allow || d.Gated {
			t.Errorf("%s: want allow without gating, got %+v", name, d)
		}
	}
}

// ── MCP: real tool calls from both protocol eras and both carriers ─────────

func TestMCPAllowsSignedToolCallInEveryEraAndCarrier(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{AllowedTools: []string{"web_search"}})
	for _, name := range []string{
		"mcp_2025-11-25_tools-call_post_header",
		"mcp_2025-11-25_tools-call_post_meta",
		"mcp_2026-07-28_tools-call_post_header",
		"mcp_2026-07-28_tools-call_post_meta",
	} {
		w, _, args := mcpToolCall(t, name)
		bundle := sign(t, iss, "/mcp/tools/call", args)
		if filepath.Ext(name) == "" && name[len(name)-4:] == "meta" {
			w = withMetaBundle(t, w, bundle)
		} else {
			w = withHeaderBundle(w, bundle)
		}
		d := gate.Decide(context.Background(), cfg, gate.MCP{}, w.inbound(t))
		if !d.Allow || !d.Gated || d.Context == nil {
			t.Errorf("%s: signed call must be allowed with context, got %+v body=%s", name, d, d.Body)
		}
	}
}

func TestMCPRejectsTamperedArguments(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	args["query"] = "harmless"
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", args)).inbound(t))
	// blindfold: contract — CLAUDE.md fail-closed + gate doc: binding mismatch → 403
	if d.Allow || d.Status != http.StatusForbidden || rpcErrorCode(t, d) != "BINDING_MISMATCH" {
		t.Fatalf("tampered arguments must be refused with BINDING_MISMATCH, got %+v %s", d, d.Body)
	}
}

func TestMCPRejectsReplayButNotFirstUse(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	in := withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", args)).inbound(t)
	if first := gate.Decide(context.Background(), cfg, gate.MCP{}, in); !first.Allow {
		t.Fatalf("first use must be allowed: %s", first.Body)
	}
	second := gate.Decide(context.Background(), cfg, gate.MCP{}, in)
	// blindfold: contract — README/api-endpoints: replay is 409 REPLAY_DETECTED
	if second.Allow || second.Status != http.StatusConflict || rpcErrorCode(t, second) != "REPLAY_DETECTED" {
		t.Fatalf("replay must be refused with 409, got %+v %s", second, second.Body)
	}
}

func TestMCPBindingMismatchDoesNotBurnNonce(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	bundle := sign(t, iss, "/mcp/tools/call", args)
	tampered := withHeaderBundle(w, bundle)
	tampered.Body = map[string]interface{}{"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]interface{}{"name": "web_search", "arguments": map[string]interface{}{"query": "other"}}}
	if d := gate.Decide(context.Background(), cfg, gate.MCP{}, tampered.inbound(t)); d.Allow {
		t.Fatal("tampered call must be refused")
	}
	if d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, bundle).inbound(t)); !d.Allow {
		t.Fatalf("an honest retry with the same bundle must still succeed: %s", d.Body)
	}
}

func TestMCPRejectsToolSwap(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	signed := sign(t, iss, "/mcp/tools/call", map[string]interface{}{"tool": "web_search", "query": "weather"})
	w.Body["params"] = map[string]interface{}{"name": "delete_all", "arguments": map[string]interface{}{"query": "weather"}}
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, signed).inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "BINDING_MISMATCH" {
		t.Fatalf("calling a tool other than the signed one must be refused, got %+v %s", d, d.Body)
	}
}

func TestMCPMissingBundleIs403NotOAuth401(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, w.inbound(t))
	// blindfold: spec — MCP auth spec: HTTP 401 triggers the client OAuth flow; DRS must not send it.
	if d.Allow || d.Status != http.StatusForbidden || rpcErrorCode(t, d) != "MISSING_BUNDLE" {
		t.Fatalf("unsigned tool call must be refused with 403 MISSING_BUNDLE, got %+v %s", d, d.Body)
	}
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(d.Body, &resp)
	// blindfold: golden — testdata/wire/mcp_2026-07-28_tools-call_post_header.json line 3 records "id": 0.
	if string(resp.ID) != "0" {
		t.Fatalf("JSON-RPC error must echo the request id, got %s", resp.ID)
	}
}

func TestMCPEnforcesPolicyAllowedTools(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{AllowedTools: []string{"web_search"}})
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	w.Body["params"] = map[string]interface{}{"name": "delete_all", "arguments": map[string]interface{}{}}
	signed := sign(t, iss, "/mcp/tools/call", map[string]interface{}{"tool": "delete_all"})
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, signed).inbound(t))
	// blindfold: contract — allowed_tools: args.tool must be in the list (pkg/policy, README policy table)
	if d.Allow || rpcErrorCode(t, d) != "POLICY_VIOLATION" {
		t.Fatalf("a tool outside allowed_tools must be refused, got %s", d.Body)
	}
}

func TestMCPRejectsHeaderBodyDisagreement(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	w.Headers["mcp-name"] = "delete_all"
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, w.inbound(t))
	// blindfold: spec — MCP 2026-07-28 Streamable HTTP: Mcp-Name must equal params.name.
	if d.Allow || d.Status != http.StatusBadRequest || rpcErrorCode(t, d) != "HEADER_MISMATCH" {
		t.Fatalf("Mcp-Name disagreeing with params.name must be refused, got %+v %s", d, d.Body)
	}
}

func TestMCPRejectsReservedToolArgument(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	w.Body["params"] = map[string]interface{}{"name": "web_search", "arguments": map[string]interface{}{"tool": "x"}}
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, w.inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "RESERVED_ARGUMENT" {
		t.Fatalf(`an argument named "tool" must be refused, got %s`, d.Body)
	}
}

func TestMCPRejectsBatches(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	in := gate.Inbound{Method: http.MethodPost, Header: http.Header{},
		Body: []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}]`)}
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, in)
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "BATCH_NOT_SUPPORTED" {
		t.Fatalf("batches must fail closed, got %s", d.Body)
	}
}

func TestMCPRejectsBundleForAnotherProtocol(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/a2a", types.Policy{}) // chain is valid for A2A; only the gate's cmd rule can refuse it
	w, _, args := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, sign(t, iss, "/a2a/SendMessage", args)).inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "CMD_MISMATCH" {
		t.Fatalf("an A2A-scoped invocation must not authorise an MCP tool call, got %s", d.Body)
	}
}

func TestMCPRejectsConflictingCarriers(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_meta")
	w = withMetaBundle(t, w, sign(t, iss, "/mcp/tools/call", args))
	w = withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", args))
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, w.inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "MULTIPLE_BUNDLES" {
		t.Fatalf("two different bundles must be refused as ambiguous, got %s", d.Body)
	}
}

func TestMCPRejectsIntegerPrecisionCollision(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	signed, err := iss.Header("/mcp/tools/call", []byte(`{"tool":"pay","amount":9007199254740992}`))
	if err != nil {
		t.Fatal(err)
	}
	in := gate.Inbound{Method: http.MethodPost, Header: bundleHeader(signed),
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":9007199254740993}}}`)}
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, in)
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "BINDING_MISMATCH" {
		t.Fatalf("2^53+1 must not bind to a signed 2^53, got %s", d.Body)
	}
}

// ── binding modes ───────────────────────────────────────────────────────────

func TestLenientModePassesMismatchAndOffSkipsBinding(t *testing.T) {
	for _, mode := range []binding.Mode{binding.ModeLenient, binding.ModeOff} {
		cfg := newConfig(t, mode)
		iss := newIssuer(t, "/mcp", types.Policy{})
		w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
		args["query"] = "other"
		d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", args)).inbound(t))
		if !d.Allow {
			t.Errorf("mode %s must not refuse a binding mismatch: %s", mode, d.Body)
		}
	}
}

func TestNewConfigRejectsUnsafeConfiguration(t *testing.T) {
	deps, err := verify.NewDefaultDeps(toolServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.NewConfig(deps, nil, binding.ModeEnforced); err == nil {
		t.Error("a nil nonce checker must be a configuration error")
	}
	if _, err := gate.NewConfig(deps, nonce.New(10, time.Minute), binding.Mode("enforce")); err == nil {
		t.Error("a mistyped binding mode must be a configuration error")
	}
}

// ── A2A ─────────────────────────────────────────────────────────────────────

func a2aArgs(t *testing.T, w wire) map[string]interface{} {
	t.Helper()
	args := map[string]interface{}{}
	for k, v := range w.Body["params"].(map[string]interface{}) {
		args[k] = v
	}
	args["tool"] = w.Body["method"]
	return args
}

func TestA2AAllowsSignedSendMessageWithPolicy(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/a2a", types.Policy{AllowedTools: []string{"SendMessage"}})
	w := loadWire(t, "a2a_1.0_SendMessage_post")
	d := gate.Decide(context.Background(), cfg, gate.A2A{}, withHeaderBundle(w, sign(t, iss, "/a2a/SendMessage", a2aArgs(t, w))).inbound(t))
	if !d.Allow || !d.Gated {
		t.Fatalf("signed SendMessage must be allowed, got %s", d.Body)
	}
}

func TestA2AIgnoresBundleInMetadata(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/a2a", types.Policy{})
	w := loadWire(t, "a2a_1.0_SendMessage_post")
	params := w.Body["params"].(map[string]interface{})
	params["metadata"] = map[string]interface{}{gate.BundleMetaKey: sign(t, iss, "/a2a/SendMessage", a2aArgs(t, w))}
	d := gate.Decide(context.Background(), cfg, gate.A2A{}, w.inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md: A2A bundles travel only in X-DRS-Bundle
	if d.Allow || rpcErrorCode(t, d) != "MISSING_BUNDLE" {
		t.Fatalf("A2A must not read a bundle from params.metadata, got %s", d.Body)
	}
}

func TestJSONRPCAdaptersRefuseUnexpectedHTTPMethods(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	for _, a := range []gate.Adapter{gate.MCP{}, gate.A2A{}} {
		for _, method := range []string{http.MethodPut, http.MethodPatch} {
			in := w.inbound(t)
			in.Method = method
			d := gate.Decide(context.Background(), cfg, a, in)
			// blindfold: standard — RFC 9110 §15.5.6: a method the endpoint does not support is 405
			if d.Allow || d.Status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s with an unsigned tool call must be refused with 405, got %+v", a.Name(), method, d)
			}
		}
	}
}

func TestJSONRPCAdaptersPassSafeNonPostMethods(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		d := gate.Decide(context.Background(), cfg, gate.MCP{}, gate.Inbound{Method: method, Header: http.Header{}})
		if !d.Allow || d.Gated {
			t.Errorf("%s carries no tool action and must pass ungated, got %+v", method, d)
		}
	}
}

func TestA2ARejectsTamperedMessage(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/a2a", types.Policy{})
	w := loadWire(t, "a2a_1.0_SendMessage_post")
	bundle := sign(t, iss, "/a2a/SendMessage", a2aArgs(t, w))
	msg := w.Body["params"].(map[string]interface{})["message"].(map[string]interface{})
	msg["parts"] = []interface{}{map[string]interface{}{"text": "wire the funds", "metadata": map[string]interface{}{}}}
	d := gate.Decide(context.Background(), cfg, gate.A2A{}, withHeaderBundle(w, bundle).inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "BINDING_MISMATCH" {
		t.Fatalf("a changed message must be refused, got %s", d.Body)
	}
}

func TestA2ARejectsUnsignedAndMCPScopedCalls(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w := loadWire(t, "a2a_1.0_SendMessage_post")
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d := gate.Decide(context.Background(), cfg, gate.A2A{}, w.inbound(t)); d.Allow || rpcErrorCode(t, d) != "MISSING_BUNDLE" {
		t.Fatalf("unsigned A2A call must be refused, got %s", d.Body)
	}
	iss := newIssuer(t, "/mcp", types.Policy{}) // chain is valid for MCP; only the gate's cmd rule can refuse it
	d := gate.Decide(context.Background(), cfg, gate.A2A{}, withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", a2aArgs(t, w))).inbound(t))
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract table
	if d.Allow || rpcErrorCode(t, d) != "CMD_MISMATCH" {
		t.Fatalf("an MCP-scoped invocation must not authorise A2A, got %s", d.Body)
	}
}

// ── plain HTTP ──────────────────────────────────────────────────────────────

func TestHTTPAdapterBindsWholeBody(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/api", types.Policy{})
	signed := sign(t, iss, "/api/expense", map[string]interface{}{"tool": "expense", "amount": 12})
	ok := gate.Decide(context.Background(), cfg, gate.HTTP{}, gate.Inbound{Method: http.MethodPost,
		Header: bundleHeader(signed), Body: []byte(`{"amount":12,"tool":"expense"}`)})
	if !ok.Allow {
		t.Fatalf("matching body must be allowed: %s", ok.Body)
	}
	missing := gate.Decide(context.Background(), cfg, gate.HTTP{}, gate.Inbound{Method: http.MethodPost, Header: http.Header{}, Body: []byte(`{}`)})
	// blindfold: contract — plain HTTP keeps the documented 401 for a missing bundle (api-endpoints.md).
	if missing.Allow || missing.Status != http.StatusUnauthorized {
		t.Fatalf("missing bundle on plain HTTP must be 401, got %+v", missing)
	}
}

// ── edge cases found by mutation testing ────────────────────────────────────

func TestA2AAllowsSignedCallWithoutParams(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/a2a", types.Policy{})
	in := gate.Inbound{Method: http.MethodPost, Header: bundleHeader(sign(t, iss, "/a2a/ListTasks", map[string]interface{}{"tool": "ListTasks"})),
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"ListTasks"}`)}
	// blindfold: contract — docs-site/src/reference/protocol-gate.md adapter table: absent params bind as {} plus {"tool": method}
	if d := gate.Decide(context.Background(), cfg, gate.A2A{}, in); !d.Allow {
		t.Fatalf("a signed A2A call without params must be allowed, got %s", d.Body)
	}
}

func TestMCPAllowsSignedToolCallWithoutArguments(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	in := gate.Inbound{Method: http.MethodPost, Header: bundleHeader(sign(t, iss, "/mcp/tools/call", map[string]interface{}{"tool": "ping"})),
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping"}}`)}
	// blindfold: contract — docs-site/src/reference/protocol-gate.md adapter table: absent arguments bind as {} plus {"tool": name}
	if d := gate.Decide(context.Background(), cfg, gate.MCP{}, in); !d.Allow {
		t.Fatalf("a signed tool call without arguments must be allowed, got %s", d.Body)
	}
}

func TestMCPRefusesEmptyPostBody(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, gate.Inbound{Method: http.MethodPost, Header: http.Header{}})
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error table: a POST that is not a JSON-RPC message is INVALID_JSONRPC (400)
	if d.Allow || d.Status != http.StatusBadRequest || rpcErrorCode(t, d) != "INVALID_JSONRPC" {
		t.Fatalf("an empty POST must be refused as invalid JSON-RPC, got %+v %s", d, d.Body)
	}
}

func TestBundleExactlyAtSizeCapIsNotRefusedForSize(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	// 87,381 = ceil(65,535 × 4/3): CLAUDE.md MCP bundle cap; the cap is inclusive.
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, strings.Repeat("A", 87_381)).inbound(t))
	if d.Allow || strings.Contains(string(d.Body), "exceeds maximum size") {
		t.Fatalf("a bundle at exactly the cap must be decoded, not size-refused, got %s", d.Body)
	}
}

// ── CommitInvocationNonce: the single replay check shared with POST /verify ──

func signedInvocation(t *testing.T) string {
	t.Helper()
	b, err := newIssuer(t, "/api", types.Policy{}).Bundle("/api/x", []byte(`{"tool":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	return b.Invocation
}

func TestCommitInvocationNonceAcceptsOnceThenRefusesReplay(t *testing.T) {
	ns := nonce.New(10, time.Hour)
	inv := signedInvocation(t)
	if d := gate.CommitInvocationNonce(ns, inv); d != nil {
		t.Fatalf("first use must be accepted, got %+v", d)
	}
	d := gate.CommitInvocationNonce(ns, inv)
	// blindfold: contract — error contract table: replay is 409 REPLAY_DETECTED
	if d == nil || d.Status != http.StatusConflict || d.Code != "REPLAY_DETECTED" {
		t.Fatalf("second use must be 409 REPLAY_DETECTED, got %+v", d)
	}
}

func TestCommitInvocationNonceFailsClosed(t *testing.T) {
	inv := signedInvocation(t)
	full := nonce.New(1, time.Hour)
	if d := gate.CommitInvocationNonce(full, signedInvocation(t)); d != nil {
		t.Fatal(d)
	}
	cases := []struct {
		name   string
		ns     nonce.Checker
		jwt    string
		status int
		code   string
	}{
		// blindfold: contract — CLAUDE.md fail-closed: no replay store means refuse, never allow.
		{"nil store", nil, inv, http.StatusServiceUnavailable, "NONCE_STORE_UNAVAILABLE"},
		// blindfold: contract — a store at capacity with nothing expired refuses rather than forgetting jtis.
		{"store full", full, inv, http.StatusServiceUnavailable, "NONCE_STORE_EXHAUSTED"},
		// blindfold: contract — an undecodable invocation is a client error.
		{"malformed", nonce.New(10, time.Hour), "not-a-jwt", http.StatusBadRequest, "MALFORMED_INVOCATION"},
	}
	for _, c := range cases {
		d := gate.CommitInvocationNonce(c.ns, c.jwt)
		if d == nil || d.Status != c.status || d.Code != c.code {
			t.Errorf("%s: want %d %s, got %+v", c.name, c.status, c.code, d)
		}
	}
}

func TestCommitInvocationNonceRefusesMissingJTI(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"cmd":"/api/x"}`))
	d := gate.CommitInvocationNonce(nonce.New(10, time.Hour), "e30."+payload+".c2ln")
	// blindfold: contract — replay protection needs a jti; its absence is a 400 MISSING_JTI.
	if d == nil || d.Status != http.StatusBadRequest || d.Code != "MISSING_JTI" {
		t.Fatalf("an invocation without jti must be refused, got %+v", d)
	}
}
