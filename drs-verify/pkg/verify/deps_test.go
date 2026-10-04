package verify_test

import (
	"context"
	"testing"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
	"github.com/OkeyAmy/DRS/drs-verify/testkit"
)

func TestNewDefaultDepsRequiresServerIdentity(t *testing.T) {
	if _, err := verify.NewDefaultDeps(""); err == nil {
		t.Fatal("empty server identity must be rejected")
	}
}

func TestNewDefaultDepsVerifiesRealChain(t *testing.T) {
	deps, err := verify.NewDefaultDeps("did:web:tools.example")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := testkit.NewIssuer("did:web:tools.example", "/mcp/tools/call", types.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := iss.Bundle("/mcp/tools/call", []byte(`{"tool":"web_search","query":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	res := verify.Chain(context.Background(), bundle, deps)
	if !res.Valid {
		t.Fatalf("real signed chain must verify with default deps: %+v", res.Error)
	}
}

func TestNewDefaultDepsRejectsOtherToolServer(t *testing.T) {
	deps, err := verify.NewDefaultDeps("did:web:tools.example")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := testkit.NewIssuer("did:web:evil.example", "/mcp/tools/call", types.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := iss.Bundle("/mcp/tools/call", []byte(`{"tool":"web_search"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res := verify.Chain(context.Background(), bundle, deps); res.Valid {
		t.Fatal("an invocation addressed to another tool server must not verify")
	}
}
