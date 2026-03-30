package store_test

import (
	"errors"
	"os"
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
	return "0000000000000000000000000000000000000000000000000000000000"
}
