package gate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/binding"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/gate"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
)

// echoHandler records what the protected handler actually received.
type echoHandler struct {
	called bool
	body   string
	ctx    *types.VerificationContext
}

func (e *echoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.called = true
	b, _ := io.ReadAll(r.Body)
	e.body = string(b)
	e.ctx = gate.VerificationContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestMiddlewareRestoresBodyAndAttachesContext(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	in := withHeaderBundle(w, sign(t, iss, "/mcp/tools/call", args)).inbound(t)

	next := &echoHandler{}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(in.Body))
	req.Header = in.Header
	rr := httptest.NewRecorder()
	gate.Middleware(cfg, gate.MCP{}, next).ServeHTTP(rr, req)

	if !next.called || next.body != string(in.Body) {
		t.Fatalf("handler must run with the original body; called=%v body=%q", next.called, next.body)
	}
	if next.ctx == nil || next.ctx.ChainDepth != 1 {
		// blindfold: contract — testkit.NewIssuer builds exactly one delegation receipt.
		t.Fatalf("verification context with chain depth 1 must be attached, got %+v", next.ctx)
	}
}

func TestMiddlewarePassesStreamGETWithoutBundle(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	next := &echoHandler{}
	rr := httptest.NewRecorder()
	gate.Middleware(cfg, gate.MCP{}, next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if !next.called {
		t.Fatal("an MCP stream GET carries no tool action and must reach the handler")
	}
}

func TestMiddlewareRefusesUnsignedToolCallWithJSONRPCError(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	in := w.inbound(t)
	next := &echoHandler{}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(in.Body))
	req.Header = in.Header
	rr := httptest.NewRecorder()
	gate.Middleware(cfg, gate.MCP{}, next).ServeHTTP(rr, req)

	if next.called {
		t.Fatal("an unsigned tool call must never reach the handler")
	}
	var resp struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("refusal must be a JSON-RPC error: %s", rr.Body)
	}
	// blindfold: contract — docs-site/src/reference/protocol-gate.md: JSON-RPC code -32010, missing bundle is 403.
	if rr.Code != http.StatusForbidden || resp.Error.Code != -32010 {
		t.Fatalf("want 403 with JSON-RPC code -32010, got %d %s", rr.Code, rr.Body)
	}
}

func TestMiddlewareRefusesOversizedBody(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	next := &echoHandler{}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"p":"` +
		strings.Repeat("a", gate.MaxBodyBytes) + `"}}}`
	rr := httptest.NewRecorder()
	gate.Middleware(cfg, gate.MCP{}, next).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(big)))
	// blindfold: contract — CLAUDE.md security rules: binding body cap is 64 KiB; error contract maps it to 413.
	if next.called || rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body above 64 KiB must be refused with 413, got %d", rr.Code)
	}
}

func TestDecideRefusesOversizedBundle(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2025-11-25_tools-call_post_header")
	d := gate.Decide(context.Background(), cfg, gate.MCP{}, withHeaderBundle(w, strings.Repeat("A", 90_000)).inbound(t))
	// blindfold: contract — CLAUDE.md: MCP bundle header cap is 85 KB; error contract code MALFORMED_BUNDLE.
	if d.Allow || rpcErrorCode(t, d) != "MALFORMED_BUNDLE" {
		t.Fatalf("a bundle above the 85 KB cap must be refused before decoding, got %s", d.Body)
	}
}

// ── POST /v1/gate ───────────────────────────────────────────────────────────

func postGate(t *testing.T, h http.Handler, req gate.GateRequest) (int, gate.Decision) {
	t.Helper()
	raw, _ := json.Marshal(req)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/gate", bytes.NewReader(raw)))
	var d gate.Decision
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	return rr.Code, d
}

func TestGateEndpointAllowsSignedCallAndRefusesReplay(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	h := gate.Handler(cfg, 1<<20)
	iss := newIssuer(t, "/mcp", types.Policy{})
	w, _, args := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	body, _ := json.Marshal(w.Body)
	req := gate.GateRequest{Protocol: "mcp", Method: http.MethodPost,
		Headers: map[string]string{"x-drs-bundle": sign(t, iss, "/mcp/tools/call", args), "mcp-name": "web_search"},
		Body:    body}

	status, first := postGate(t, h, req)
	if status != http.StatusOK || !first.Allow || !first.Gated {
		t.Fatalf("signed call must be allowed via /v1/gate, got %d %+v", status, first)
	}
	_, second := postGate(t, h, req)
	// blindfold: contract — error contract: replay is 409.
	if second.Allow || second.Status != http.StatusConflict {
		t.Fatalf("replay through /v1/gate must be refused with 409, got %+v", second)
	}
}

func TestGateEndpointHonoursForwardedMcpNameHeader(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	w, _, _ := mcpToolCall(t, "mcp_2026-07-28_tools-call_post_header")
	body, _ := json.Marshal(w.Body)
	_, d := postGate(t, gate.Handler(cfg, 1<<20), gate.GateRequest{Protocol: "mcp", Method: http.MethodPost,
		Headers: map[string]string{"mcp-name": "delete_all"}, Body: body})
	// blindfold: contract — error contract: HEADER_MISMATCH is 400.
	if d.Allow || d.Status != http.StatusBadRequest {
		t.Fatalf("a forwarded Mcp-Name that disagrees with the body must be refused, got %+v", d)
	}
}

func TestGateEndpointIgnoresNonAllowlistedHeaders(t *testing.T) {
	cfg := newConfig(t, binding.ModeEnforced)
	iss := newIssuer(t, "/api", types.Policy{})
	signed := sign(t, iss, "/api/x", map[string]interface{}{"tool": "x"})
	// The bundle is smuggled under a header name the gate must not read.
	_, d := postGate(t, gate.Handler(cfg, 1<<20), gate.GateRequest{Protocol: "http", Method: http.MethodPost,
		Headers: map[string]string{"authorization": signed}, Body: json.RawMessage(`{"tool":"x"}`)})
	// blindfold: contract — only allowlisted headers are forwarded; http adapter answers a missing bundle with 401.
	if d.Allow || d.Status != http.StatusUnauthorized {
		t.Fatalf("headers outside the allowlist must be ignored, got %+v", d)
	}
}

func TestGateEndpointRejectsBadRequests(t *testing.T) {
	h := gate.Handler(newConfig(t, binding.ModeEnforced), 1<<20)
	status, _ := postGate(t, h, gate.GateRequest{Protocol: "grpc", Method: http.MethodPost})
	// blindfold: contract — only http, mcp and a2a adapters exist; unknown protocol is a 400.
	if status != http.StatusBadRequest {
		t.Errorf("unknown protocol must be 400, got %d", status)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/gate", nil))
	// blindfold: standard — RFC 9110 §15.5.6: an unsupported method is 405.
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/gate must be 405, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/gate", strings.NewReader("{")))
	// blindfold: contract — malformed gate request JSON is a client error (400).
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON must be 400, got %d", rr.Code)
	}
}

func TestGateEndpointAcceptsBodyExactlyAtCap(t *testing.T) {
	h := gate.Handler(newConfig(t, binding.ModeEnforced), 1<<20)
	prefix, suffix := `{"p":"`, `"}`
	body := prefix + strings.Repeat("a", gate.MaxBodyBytes-len(prefix)-len(suffix)) + suffix
	status, _ := postGate(t, h, gate.GateRequest{Protocol: "http", Method: http.MethodPost, Body: json.RawMessage(body)})
	// blindfold: contract — CLAUDE.md: 64 KiB cap is inclusive; /v1/gate always answers 200 with a decision
	if status != http.StatusOK {
		t.Fatalf("a body of exactly 64 KiB must be decided, not refused with %d", status)
	}
}
