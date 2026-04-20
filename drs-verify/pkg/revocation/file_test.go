package revocation

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileBackedStore_RevokedIndicesSurviveReopen(t *testing.T) {
	// The core guarantee: after Revoke returns nil, a fresh process opening
	// the same file must see the same set of revoked indices.
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.log")

	s1, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	for _, idx := range []uint64{7, 42, 1_000_000} {
		if err := s1.Revoke(idx); err != nil {
			t.Fatalf("Revoke(%d): %v", idx, err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	// Simulate a restart by opening a fresh instance on the same path.
	s2, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer func() { _ = s2.Close() }()

	for _, idx := range []uint64{7, 42, 1_000_000} {
		if !s2.IsRevoked(idx) {
			t.Errorf("expected %d to remain revoked after reopen, got IsRevoked=false", idx)
		}
	}
	// Sanity — untouched indices stay not revoked.
	if s2.IsRevoked(999_999) {
		t.Error("non-revoked index reported as revoked after reopen")
	}
}

func TestFileBackedStore_MissingFileIsEmptyStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist-yet.log")

	s, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open missing: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.IsRevoked(1) {
		t.Error("fresh store reports revoked for index 1")
	}
}

func TestFileBackedStore_RevokeWritesOneLinePerCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.log")

	s, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Revoke(1); err != nil {
		t.Fatalf("Revoke(1): %v", err)
	}
	if err := s.Revoke(2); err != nil {
		t.Fatalf("Revoke(2): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	want := "1\n2\n"
	if string(b) != want {
		t.Errorf("file content = %q, want %q", string(b), want)
	}
}

func TestFileBackedStore_MalformedLinesAreSkippedOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.log")

	// Operator-edited file with comments, blank lines, and a garbage line.
	content := strings.Join([]string{
		"# emergency revoke on 2026-04-20 — investigating",
		"",
		"42",
		"not-a-number",
		"   ",
		"1000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	s, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	if !s.IsRevoked(42) {
		t.Error("42 should be revoked")
	}
	if !s.IsRevoked(1000) {
		t.Error("1000 should be revoked")
	}
	// Malformed lines must not have poisoned the store.
	if s.IsRevoked(0) {
		t.Error("0 should not be revoked (parsed from 'not-a-number' would be wrong)")
	}
}

func TestFileBackedStore_ConcurrentRevokesAreSerialised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.log")

	s, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			if err := s.Revoke(uint64(i)); err != nil {
				t.Errorf("Revoke(%d): %v", i, err)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if !s.IsRevoked(uint64(i)) {
			t.Errorf("index %d not revoked after concurrent Revoke calls", i)
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-open and verify all n are still revoked — proves no interleaved writes
	// produced a corrupt line that failed to parse.
	s2, err := OpenFileBackedRevocationStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	for i := 0; i < n; i++ {
		if !s2.IsRevoked(uint64(i)) {
			t.Errorf("index %d lost after concurrent writes + reopen", i)
		}
	}
}

func TestFileBackedStore_SatisfiesLocalStoreInterface(t *testing.T) {
	// Compile-time assertion via type assignment: FileBackedRevocationStore
	// must satisfy LocalStore so admin_handler can take either backend.
	var _ LocalStore = (*FileBackedRevocationStore)(nil)
	var _ LocalStore = (*LocalRevocationStore)(nil)
}
