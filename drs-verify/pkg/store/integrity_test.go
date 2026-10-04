package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func keyFor(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestIntegrityStore_DetectsTamperedReceipt(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFilesystemStore(dir, 0)
	s := NewIntegrityStore(fs)

	key := keyFor("real-receipt")
	if err := s.Put(key, "real-receipt"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Attacker with disk access overwrites the stored file directly.
	path, _ := fs.hashPath(key)
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	// invariant: content-addressed store must reject a value whose hash no longer matches its key
	if _, err := s.Get(key); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered read: got %v, want ErrIntegrity", err)
	}
}

func TestIntegrityStore_PassesUntampered(t *testing.T) {
	dir := t.TempDir()
	s := NewIntegrityStore(mustFS(t, dir))
	// contract: Put stores exactly the value provided; Get returns it unchanged
	const value = "good"
	key := keyFor(value)
	_ = s.Put(key, value)
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("untampered read error: %v", err)
	}
	// contract: the returned value must equal exactly what was stored
	if got != value {
		t.Fatalf("untampered read: got %q, want %q", got, value) // blindfold: contract — Put/Get round-trip must be identity
	}
}

func TestIntegrityStore_SkipsTstTokens(t *testing.T) {
	dir := t.TempDir()
	s := NewIntegrityStore(mustFS(t, dir))
	// .tst value is not content-addressed by the key; must pass through.
	key := keyFor("anything") + ".tst"
	// contract: RFC 3161 timestamp tokens are opaque blobs; integrity check is the TSA signature, not the key hash
	const token = "opaque-rfc3161-token-bytes"
	_ = s.Put(key, token)
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf(".tst passthrough error: %v", err)
	}
	// contract: .tst passthrough must return the token verbatim without ErrIntegrity
	if got != token {
		t.Fatalf(".tst passthrough: got %q, want %q", got, token) // blindfold: contract — .tst keys bypass hash check, value is identity
	}
}

func mustFS(t *testing.T, dir string) *FilesystemStore {
	t.Helper()
	fs, err := NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	return fs
}
