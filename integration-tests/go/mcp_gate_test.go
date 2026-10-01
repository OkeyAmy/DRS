// Live Go suite: the official Go MCP SDK (client and server) talking through
// drs-verify's gate.Middleware — the path a Go tool server uses. Real
// Ed25519 chains from drs-verify/testkit, no stubs.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/binding"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/gate"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
	"github.com/OkeyAmy/DRS/drs-verify/testkit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const toolServer = "did:web:tools.example"

type searchIn struct {
	Query string `json:"query"`
}

type ledger struct {
	mu  sync.Mutex
	ran []string
}

func (l *ledger) add(s string) { l.mu.Lock(); l.ran = append(l.ran, s); l.mu.Unlock() }
func (l *ledger) has(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.ran {
		if r == s {
			return true
		}
	}
	return false
}

func startGatedServer(t *testing.T) (*httptest.Server, *ledger) {
	t.Helper()
	ran := &ledger{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "go-live", Version: "1.0.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "web_search"}, func(_ context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, any, error) {
		ran.add("web_search:" + in.Query)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "results for " + in.Query}}}, nil, nil
	})
	deps, err := verify.NewDefaultDeps(toolServer)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gate.NewConfig(deps, nonce.New(1000, time.Hour), binding.ModeEnforced)
	if err != nil {
		t.Fatal(err)
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(gate.Middleware(cfg, gate.MCP{}, handler))
	t.Cleanup(ts.Close)
	return ts, ran
}

// signingTransport signs each tools/call with `lie` applied to the args it
// actually sends (identity for an honest agent).
type signingTransport struct {
	issuer *testkit.Issuer
	lie    func(args map[string]any) map[string]any
}

func (s signingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body == nil || s.issuer == nil {
		return http.DefaultTransport.RoundTrip(r)
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) == nil && msg.Method == "tools/call" {
		args := map[string]any{"tool": msg.Params.Name}
		for k, v := range msg.Params.Arguments {
			args[k] = v
		}
		signed, err := json.Marshal(s.lie(args))
		if err != nil {
			return nil, err
		}
		h, err := s.issuer.Header("/mcp/tools/call", signed)
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.Header.Set(gate.BundleHeader, h)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, url string, rt http.RoundTripper) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "go-live-client", Version: "1.0.0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: rt},
	}, nil)
	if err != nil {
		t.Fatalf("connect must succeed without a bundle (handshake is not gated): %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func issuer(t *testing.T) *testkit.Issuer {
	t.Helper()
	iss, err := testkit.NewIssuer(toolServer, "/mcp", types.Policy{AllowedTools: []string{"web_search"}})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func honest(a map[string]any) map[string]any { return a }

func TestGoSDKHonestCallExecutes(t *testing.T) {
	ts, ran := startGatedServer(t)
	cs := connect(t, ts.URL, signingTransport{issuer: issuer(t), lie: honest})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "web_search", Arguments: map[string]any{"query": "go"}})
	if err != nil || res.IsError {
		t.Fatalf("honest signed call must succeed: err=%v res=%+v", err, res)
	}
	if !ran.has("web_search:go") {
		t.Fatal("the tool must have executed")
	}
}

func TestGoSDKTamperedCallNeverExecutes(t *testing.T) {
	ts, ran := startGatedServer(t)
	lie := func(a map[string]any) map[string]any { a["query"] = "harmless"; return a }
	cs := connect(t, ts.URL, signingTransport{issuer: issuer(t), lie: lie})
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "web_search", Arguments: map[string]any{"query": "exfil"}})
	// blindfold: contract — docs-site/src/reference/protocol-gate.md error contract: tampering is BINDING_MISMATCH
	if err == nil || !strings.Contains(err.Error(), "BINDING_MISMATCH") {
		t.Fatalf("tampered call must be refused with BINDING_MISMATCH, got %v", err)
	}
	if ran.has("web_search:exfil") {
		t.Fatal("a tampered call must never execute")
	}
}

func TestGoSDKUnsignedCallNeverExecutes(t *testing.T) {
	ts, ran := startGatedServer(t)
	cs := connect(t, ts.URL, signingTransport{})
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "web_search", Arguments: map[string]any{"query": "unsigned"}})
	// blindfold: contract — error contract: unsigned gated call is MISSING_BUNDLE
	if err == nil || !strings.Contains(err.Error(), "MISSING_BUNDLE") {
		t.Fatalf("unsigned call must be refused with MISSING_BUNDLE, got %v", err)
	}
	if ran.has("web_search:unsigned") {
		t.Fatal("an unsigned call must never execute")
	}
}

func TestGoSDKListToolsNeedsNoBundle(t *testing.T) {
	ts, _ := startGatedServer(t)
	cs := connect(t, ts.URL, signingTransport{})
	res, err := cs.ListTools(context.Background(), nil)
	// blindfold: example — startGatedServer registers exactly one tool, web_search
	if err != nil || len(res.Tools) != 1 || res.Tools[0].Name != "web_search" {
		t.Fatalf("tools/list must pass ungated, got %v %+v", err, res)
	}
}
