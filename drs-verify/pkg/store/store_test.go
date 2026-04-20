package store_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/store"
)

func testStoreContract(t *testing.T, s store.Store) {
	t.Helper()

	const key = "sha256:aabbccdd00112233445566778899aabb00112233445566778899aabb00112233"
	const jwt = "header.payload.sig"

	// Get on missing key returns ErrNotFound
	if _, err := s.Get(key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get on missing key: want ErrNotFound, got %v", err)
	}

	// Put then Get returns the same value
	if err := s.Put(key, jwt); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if got != jwt {
		t.Errorf("Get returned %q, want %q", got, jwt)
	}

	// Overwrite is silent
	const updated = "header.newpayload.newsig"
	if err := s.Put(key, updated); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	got, err = s.Get(key)
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if got != updated {
		t.Errorf("overwrite: got %q, want %q", got, updated)
	}

	// Delete removes the entry
	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: want ErrNotFound, got %v", err)
	}

	// Double-delete is a no-op
	if err := s.Delete(key); err != nil {
		t.Errorf("double Delete returned error: %v", err)
	}
}

func TestMemoryStoreContract(t *testing.T) {
	s, err := store.NewMemoryStore(100)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	testStoreContract(t, s)
}

func TestMemoryStoreLRUEviction(t *testing.T) {
	s, err := store.NewMemoryStore(2) // cap at 2 entries
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	if err := s.Put("sha256:aaaa"+pad(), "jwt-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("sha256:bbbb"+pad(), "jwt-b"); err != nil {
		t.Fatal(err)
	}
	// Adding a third entry should evict the least-recently-used
	if err := s.Put("sha256:cccc"+pad(), "jwt-c"); err != nil {
		t.Fatal(err)
	}

	// At most 2 of the 3 keys can be present
	found := 0
	for _, k := range []string{"sha256:aaaa" + pad(), "sha256:bbbb" + pad(), "sha256:cccc" + pad()} {
		if _, err := s.Get(k); err == nil {
			found++
		}
	}
	if found > 2 {
		t.Errorf("LRU eviction failed: found %d entries, expected at most 2", found)
	}
}

func TestFilesystemStoreContract(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	testStoreContract(t, s)
}

func TestFilesystemStoreExpiry(t *testing.T) {
	dir := t.TempDir()
	// 1ms TTL — entries expire almost immediately
	s, err := store.NewFilesystemStore(dir, time.Millisecond)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}

	const key = "sha256:deadbeef00112233445566778899aabb00112233445566778899aabb00112233"
	if err := s.Put(key, "jwt"); err != nil {
		t.Fatal(err)
	}

	// Back-date the file's mtime by 1 second
	path := dir + "/dead/deadbeef00112233445566778899aabb00112233445566778899aabb00112233.jwt"
	past := time.Now().Add(-time.Second)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	if _, err := s.Get(key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired entry: want ErrNotFound, got %v", err)
	}
}

func TestFilesystemStoreCreatesDir(t *testing.T) {
	dir := t.TempDir() + "/new/nested/dir"
	if _, err := store.NewFilesystemStore(dir, time.Hour); err != nil {
		t.Errorf("NewFilesystemStore should create the base dir: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("base dir should exist after creation: %v", err)
	}
}

// pad returns a 60-character suffix to fill out a 64-char hex digest.
func pad() string {
	return "000000000000000000000000000000000000000000000000000000000000"
}

func TestFilesystemStorePathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}

	malicious := []string{
		"sha256:../../../../etc/passwd",
		"sha256:../evil",
		"sha256:abc",             // too short — not 64 hex chars
		"sha256:" + strings.Repeat("a", 63), // 63 chars — one short
		"sha256:" + strings.Repeat("G", 64), // uppercase — not hex
		"sha256:" + strings.Repeat("a", 65), // too long
	}

	for _, hash := range malicious {
		if err := s.Put(hash, "jwt"); err == nil {
			t.Errorf("Put(%q) should have returned an error", hash)
		}
		if _, err := s.Get(hash); err == nil {
			t.Errorf("Get(%q) should have returned an error", hash)
		}
		if err := s.Delete(hash); err == nil {
			t.Errorf("Delete(%q) should have returned an error", hash)
		}
	}
}

func TestFilesystemStoreValidHash(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}

	// exactly 64 lowercase hex chars is valid
	valid := "sha256:" + strings.Repeat("a1", 32)
	if err := s.Put(valid, "test.jwt"); err != nil {
		t.Fatalf("Put with valid hash: %v", err)
	}
	got, err := s.Get(valid)
	if err != nil {
		t.Fatalf("Get with valid hash: %v", err)
	}
	if got != "test.jwt" {
		t.Errorf("Get returned %q, want %q", got, "test.jwt")
	}
}

func TestFilesystemStoreTstExtensionAccepted(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	// Tier3Store stores RFC 3161 timestamp tokens under hash + ".tst".
	// The filesystem store must accept this key shape.
	tstKey := "sha256:" + strings.Repeat("a1", 32) + ".tst"
	if err := s.Put(tstKey, "token-bytes"); err != nil {
		t.Fatalf("Put with .tst key: %v", err)
	}
	got, err := s.Get(tstKey)
	if err != nil {
		t.Fatalf("Get with .tst key: %v", err)
	}
	if got != "token-bytes" {
		t.Errorf("Get returned %q, want %q", got, "token-bytes")
	}
	if err := s.Delete(tstKey); err != nil {
		t.Errorf("Delete with .tst key: %v", err)
	}
}

func TestFilesystemStoreJwtAndTstDisjoint(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	// JWT and TST keys for the same digest must map to distinct files,
	// so storing a token does not overwrite the receipt.
	digest := "sha256:" + strings.Repeat("cd", 32)
	if err := s.Put(digest, "receipt-jwt"); err != nil {
		t.Fatalf("Put jwt: %v", err)
	}
	if err := s.Put(digest+".tst", "timestamp-token"); err != nil {
		t.Fatalf("Put tst: %v", err)
	}
	gotJWT, err := s.Get(digest)
	if err != nil || gotJWT != "receipt-jwt" {
		t.Errorf("Get jwt: got %q, err=%v; want %q", gotJWT, err, "receipt-jwt")
	}
	gotTST, err := s.Get(digest + ".tst")
	if err != nil || gotTST != "timestamp-token" {
		t.Errorf("Get tst: got %q, err=%v; want %q", gotTST, err, "timestamp-token")
	}
}

func TestFilesystemStoreRejectsUnknownExtensions(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	bad := []string{
		"sha256:" + strings.Repeat("a1", 32) + ".exe",
		"sha256:" + strings.Repeat("a1", 32) + ".evil",
		"sha256:" + strings.Repeat("a1", 32) + ".JWT", // uppercase
		"sha256:" + strings.Repeat("a1", 32) + ".",
		"sha256:" + strings.Repeat("a1", 32) + "..tst", // double dot
	}
	for _, key := range bad {
		if err := s.Put(key, "x"); err == nil {
			t.Errorf("Put(%q) should have returned an error", key)
		}
	}
}
