package verify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
)

// These tests lock in the auth-bypass fixes from the VULN-FINDINGS pass:
// F-003 (hop-by-hop + leaf cmd narrowing), F-015 (empty root cmd),
// F-016 (child exp omission), F-055 (empty consent fields). They exercise the
// real Chain() path with signed receipts — no mocks, no hardcoded results.

// drBuilder builds a signed delegation receipt with caller-chosen fields.
func drBuilder(key testKey, iss, sub, aud, cmd string, now int64, exp *int64, prevHash *string) (types.DelegationReceipt, string) {
	dr := types.DelegationReceipt{
		Iss:        iss,
		Sub:        sub,
		Aud:        aud,
		DrsV:       "4.0",
		DrsType:    "delegation-receipt",
		Cmd:        cmd,
		Policy:     types.Policy{},
		Nbf:        now - 60,
		Exp:        exp,
		Iat:        now,
		Jti:        fmt.Sprintf("dr:%s-%d", iss, now),
		PrevDRHash: prevHash,
	}
	return dr, signJWT(key.prv, dr)
}

func invWithCmd(key testKey, iss, sub, cmd string, drChain []string, now int64) string {
	inv := types.InvocationReceipt{
		Iss:        iss,
		Sub:        sub,
		DrsV:       "4.0",
		DrsType:    "invocation-receipt",
		Cmd:        cmd,
		Args:       map[string]interface{}{},
		DrChain:    drChain,
		ToolServer: "mcp://tools/server",
		Iat:        now,
		Jti:        fmt.Sprintf("inv:%s-%d", iss, now),
	}
	return signJWT(key.prv, inv)
}

// F-003: invocation cmd must be a sub-path of the LEAF receipt's cmd, not just
// the root's. A chain that narrows /tools → /tools/read must reject /tools/write.
func TestInvocationCmdMustBeSubpathOfLeaf(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	_, jwt1 := drBuilder(k1, k1.did, k0.did, k2.did, "/tools/read", now, &exp, &h0)
	h1 := computeChainHash(jwt1)
	inv := invWithCmd(k2, k2.did, k0.did, "/tools/write", []string{h0, h1}, now)

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid {
		t.Fatal("expected COMMAND_MISMATCH: invocation /tools/write escaped leaf scope /tools/read")
	}
	if res.Error.Code != "COMMAND_MISMATCH" {
		t.Errorf("expected COMMAND_MISMATCH, got %q", res.Error.Code)
	}
}

// F-003: each receipt's cmd must narrow its PARENT's, not merely the root's.
func TestCmdNarrowingIsHopByHop(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	_, jwt1 := drBuilder(k1, k1.did, k0.did, k2.did, "/tools/read", now, &exp, &h0)
	h1 := computeChainHash(jwt1)
	// receipt2 widens back to /tools/write — a sub-path of root /tools but NOT of parent /tools/read.
	k3 := newTestKey(t)
	_, jwt2 := drBuilder(k2, k2.did, k0.did, k3.did, "/tools/write", now, &exp, &h1)
	h2 := computeChainHash(jwt2)
	inv := invWithCmd(k3, k3.did, k0.did, "/tools/write", []string{h0, h1, h2}, now)

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1, jwt2},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid || res.Error.Code != "COMMAND_MISMATCH" {
		t.Errorf("expected COMMAND_MISMATCH for non-monotonic narrowing, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// F-015: an empty root cmd must be rejected (HasPrefix(x, "") is always true).
func TestEmptyRootCmdRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	inv := invWithCmd(k1, k1.did, k0.did, "/admin/delete", []string{h0}, now)

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid || res.Error.Code != "INVALID_ROOT_CMD" {
		t.Errorf("expected INVALID_ROOT_CMD, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// F-016: a child that omits exp while the parent sets one is a temporal escalation.
func TestChildOmittingExpWhenParentHasOneRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	// child omits exp (nil) — would otherwise outlive the time-bounded parent.
	_, jwt1 := drBuilder(k1, k1.did, k0.did, k2.did, "/tools", now, nil, &h0)
	h1 := computeChainHash(jwt1)
	inv := invWithCmd(k2, k2.did, k0.did, "/tools", []string{h0, h1}, now)

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid || res.Error.Code != "TEMPORAL_BOUNDS_VIOLATION" {
		t.Errorf("expected TEMPORAL_BOUNDS_VIOLATION, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// F-055: a human-rooted chain with a structurally-present but empty consent
// record must be rejected, not recorded as "consent present".
func TestEmptyHumanConsentRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600
	human := "human"

	dr := types.DelegationReceipt{
		Iss:         k0.did,
		Sub:         k0.did,
		Aud:         k1.did,
		DrsV:        "4.0",
		DrsType:     "delegation-receipt",
		Cmd:         "/tools",
		Policy:      types.Policy{},
		Nbf:         now - 60,
		Exp:         &exp,
		Iat:         now,
		Jti:         fmt.Sprintf("dr:%s-%d", k0.did, now),
		DrsRootType: &human,
		DrsConsent:  &types.ConsentRecord{}, // all empty fields
	}
	jwt0 := signJWT(k0.prv, dr)
	h0 := computeChainHash(jwt0)
	inv := invWithCmd(k1, k1.did, k0.did, "/tools", []string{h0}, now)

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid || res.Error.Code != "INVALID_CONSENT" {
		t.Errorf("expected INVALID_CONSENT, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// F-014: when no SERVER_IDENTITY is configured, an invocation that names a
// specific tool_server must be rejected fail-closed (not silently accepted),
// so a bundle minted for one server cannot verify on an unconfigured one.
func TestToolServerBindingFailsClosedWithoutServerIdentity(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	inv := invWithCmd(k1, k1.did, k0.did, "/tools", []string{h0}, now) // ToolServer set

	deps := testDeps(t)
	deps.ServerIdentity = "" // operator left SERVER_IDENTITY unset

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    inv,
	}, deps)

	if res.Valid || res.Error.Code != "TOOL_SERVER_MISMATCH" {
		t.Errorf("expected TOOL_SERVER_MISMATCH, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// F-022/F-025: an invocation older than MaxInvocationAge is rejected, closing
// the replay window that opens once the nonce store evicts its JTI.
func TestStaleInvocationRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 36000

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now-7200, &exp, nil)
	h0 := computeChainHash(jwt0)
	// invocation issued 2h ago; receipts still valid, but invocation is stale.
	inv := invWithCmd(k1, k1.did, k0.did, "/tools", []string{h0}, now-7200)

	deps := testDeps(t)
	deps.MaxInvocationAge = time.Hour

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    inv,
	}, deps)

	if res.Valid || res.Error.Code != "INVOCATION_STALE" {
		t.Errorf("expected INVOCATION_STALE, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}

// A future-dated invocation beyond the clock-skew allowance is rejected.
func TestFutureInvocationRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 36000

	_, jwt0 := drBuilder(k0, k0.did, k0.did, k1.did, "/tools", now, &exp, nil)
	h0 := computeChainHash(jwt0)
	inv := invWithCmd(k1, k1.did, k0.did, "/tools", []string{h0}, now+3600) // 1h in the future

	res := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    inv,
	}, testDeps(t))

	if res.Valid || res.Error.Code != "INVOCATION_NOT_YET_VALID" {
		t.Errorf("expected INVOCATION_NOT_YET_VALID, got valid=%v code=%q", res.Valid, res.Error.Code)
	}
}
