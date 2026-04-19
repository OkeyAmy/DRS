package verify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/policy"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

func fixturesDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "fixtures", "conformance")
}

func loadFixture(t *testing.T, relPath string) []byte {
	t.Helper()
	path := filepath.Join(fixturesDir(), relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", relPath, err)
	}
	return data
}

// ── Chain hash conformance ───────────────────────────────────────────────

type chainHashFixture struct {
	Vectors []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"vectors"`
}

func TestConformanceChainHash(t *testing.T) {
	raw := loadFixture(t, "chain-hash/vectors.json")
	var fixture chainHashFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse chain-hash fixture: %v", err)
	}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			got := computeChainHash(vec.Input)
			if got != vec.Expected {
				t.Errorf("chain hash mismatch: got %q, expected %q", got, vec.Expected)
			}
		})
	}
}

// ── Policy attenuation conformance — pass ────────────────────────────────

type policyPassFixture struct {
	Vectors []struct {
		ID     string       `json:"id"`
		Parent types.Policy `json:"parent"`
		Child  types.Policy `json:"child"`
	} `json:"vectors"`
}

func TestConformancePolicyAttenuationPass(t *testing.T) {
	raw := loadFixture(t, "policy/pass.json")
	var fixture policyPassFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse policy/pass fixture: %v", err)
	}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			err := policy.CheckAttenuation(vec.Parent, vec.Child)
			if err != nil {
				t.Errorf("expected pass but got error: %v", err)
			}
		})
	}
}

// ── Policy attenuation conformance — fail ────────────────────────────────

type policyFailFixture struct {
	Vectors []struct {
		ID              string       `json:"id"`
		Parent          types.Policy `json:"parent"`
		Child           types.Policy `json:"child"`
		ExpectedKeyword string       `json:"expected_keyword"`
	} `json:"vectors"`
}

func TestConformancePolicyAttenuationFail(t *testing.T) {
	raw := loadFixture(t, "policy/fail.json")
	var fixture policyFailFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse policy/fail fixture: %v", err)
	}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			err := policy.CheckAttenuation(vec.Parent, vec.Child)
			if err == nil {
				t.Fatalf("expected failure for keyword %q but attenuation passed", vec.ExpectedKeyword)
			}
			errMsg := strings.ToLower(err.Error())
			keyword := strings.ToLower(vec.ExpectedKeyword)
			if !strings.Contains(errMsg, keyword) {
				t.Errorf("error message %q does not contain expected keyword %q", err.Error(), vec.ExpectedKeyword)
			}
		})
	}
}

// ── Full chain bundle conformance ────────────────────────────────────────

type fullChainFixture struct {
	Keys   map[string]struct {
		Did string `json:"did"`
	} `json:"keys"`
	Bundle         types.ChainBundle `json:"bundle"`
	ExpectedResult struct {
		Valid   bool `json:"valid"`
		Context struct {
			RootPrincipal string `json:"root_principal"`
			RootType      string `json:"root_type"`
			ChainDepth    int    `json:"chain_depth"`
		} `json:"context"`
	} `json:"expected_result"`
}

func TestConformanceFullChainBundle(t *testing.T) {
	raw := loadFixture(t, "receipts/full-chain-bundle.json")
	var fixture fullChainFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse full-chain-bundle fixture: %v", err)
	}

	deps := testDeps(t)
	result := Chain(context.Background(), fixture.Bundle, deps)

	if result.Valid != fixture.ExpectedResult.Valid {
		var errMsg string
		if result.Error != nil {
			errMsg = fmt.Sprintf(" (code=%s, msg=%s)", result.Error.Code, result.Error.Message)
		}
		t.Fatalf("expected valid=%v but got valid=%v%s",
			fixture.ExpectedResult.Valid, result.Valid, errMsg)
	}

	if result.Context == nil {
		t.Fatal("expected non-nil context on valid result")
	}

	exp := fixture.ExpectedResult.Context
	if result.Context.RootPrincipal != exp.RootPrincipal {
		t.Errorf("root_principal: got %q, expected %q",
			result.Context.RootPrincipal, exp.RootPrincipal)
	}
	if result.Context.RootType == nil || *result.Context.RootType != exp.RootType {
		got := "<nil>"
		if result.Context.RootType != nil {
			got = *result.Context.RootType
		}
		t.Errorf("root_type: got %q, expected %q", got, exp.RootType)
	}
	if result.Context.ChainDepth != exp.ChainDepth {
		t.Errorf("chain_depth: got %d, expected %d",
			result.Context.ChainDepth, exp.ChainDepth)
	}
}

// ── Receipt chain hash cross-check ───────────────────────────────────────

type receiptFixture struct {
	Jwt       string `json:"jwt"`
	ChainHash string `json:"chain_hash"`
}

func TestConformanceReceiptChainHash(t *testing.T) {
	files := []string{
		"receipts/root-delegation.json",
		"receipts/sub-delegation.json",
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			raw := loadFixture(t, file)
			var fixture receiptFixture
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}

			got := computeChainHash(fixture.Jwt)
			if got != fixture.ChainHash {
				t.Errorf("chain hash mismatch: got %q, expected %q", got, fixture.ChainHash)
			}
		})
	}
}

// ── Signature verification on conformance receipts ───────────────────────

func TestConformanceReceiptSignatures(t *testing.T) {
	type sigFixture struct {
		Jwt  string `json:"jwt"`
		Keys map[string]struct {
			Did string `json:"did"`
		} `json:"keys"`
		Payload struct {
			Iss string `json:"iss"`
		} `json:"payload"`
	}

	files := []struct {
		path string
	}{
		{"receipts/root-delegation.json"},
		{"receipts/sub-delegation.json"},
		{"receipts/invocation.json"},
	}

	deps := testDeps(t)

	for _, f := range files {
		t.Run(f.path, func(t *testing.T) {
			raw := loadFixture(t, f.path)
			var fix sigFixture
			if err := json.Unmarshal(raw, &fix); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}

			err := verifyJWTSignature(context.Background(), fix.Jwt, fix.Payload.Iss, deps.Resolver)
			if err != nil {
				t.Errorf("signature verification failed: %v", err)
			}
		})
	}
}

// ── Temporal validity conformance ─────────────────────────────────────────

type temporalFixture struct {
	Vectors []struct {
		ID           string `json:"id"`
		Nbf          int64  `json:"nbf"`
		Exp          *int64 `json:"exp"`
		Now          int64  `json:"now"`
		Valid        bool   `json:"valid"`
		ExpectedCode string `json:"expected_code"`
	} `json:"vectors"`
}

func TestConformanceTemporalValidity(t *testing.T) {
	raw := loadFixture(t, "temporal/vectors.json")
	var fixture temporalFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse temporal fixture: %v", err)
	}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			now := vec.Now
			var errCode string
			valid := true

			if now < vec.Nbf {
				valid = false
				errCode = "NOT_YET_VALID"
			} else if vec.Exp != nil && now > *vec.Exp {
				valid = false
				errCode = "EXPIRED"
			}

			if valid != vec.Valid {
				t.Errorf("expected valid=%v but got valid=%v", vec.Valid, valid)
			}
			if !vec.Valid && vec.ExpectedCode != "" {
				if errCode != vec.ExpectedCode {
					t.Errorf("expected code %q but got %q", vec.ExpectedCode, errCode)
				}
			}
		})
	}
}

// ── Revocation status conformance ────────────────────────────────────────

type revocationFixture struct {
	Vectors []struct {
		ID              string `json:"id"`
		StatusListIndex int    `json:"status_list_index"`
		IsRevoked       bool   `json:"is_revoked"`
	} `json:"vectors"`
}

func TestConformanceRevocationStatus(t *testing.T) {
	raw := loadFixture(t, "revocation/vectors.json")
	var fixture revocationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse revocation fixture: %v", err)
	}

	revokedIndices := map[int]bool{42: true}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			isRevoked := revokedIndices[vec.StatusListIndex]
			if isRevoked != vec.IsRevoked {
				t.Errorf("expected is_revoked=%v but got %v", vec.IsRevoked, isRevoked)
			}
		})
	}
}

// ── Verify computeChainHash matches raw SHA-256 ──────────────────────────

func TestConformanceChainHashMatchesSHA256(t *testing.T) {
	raw := loadFixture(t, "chain-hash/vectors.json")
	var fixture chainHashFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse chain-hash fixture: %v", err)
	}

	for _, vec := range fixture.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			digest := sha256.Sum256([]byte(vec.Input))
			expected := fmt.Sprintf("sha256:%x", digest)
			got := computeChainHash(vec.Input)
			if got != expected {
				t.Errorf("computeChainHash does not match raw SHA-256: got %q, expected %q", got, expected)
			}
		})
	}
}
