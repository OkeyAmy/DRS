package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTTL     = 48 * time.Hour
	filePermission = 0o600
	dirPermission  = 0o700
)

// validKeyRe matches a SHA-256 digest (64 lowercase hex characters) with an
// optional ".jwt" or ".tst" extension. Anything else is rejected at the
// path-construction boundary to prevent traversal (../), separators, null
// bytes, uppercase, wrong length, and unknown extensions.
var validKeyRe = regexp.MustCompile(`^([0-9a-f]{64})(?:\.(jwt|tst))?$`)

// FilesystemStore is a Tier-1 DR store backed by the local filesystem.
//
// Layout: <baseDir>/<hash_prefix_4>/<hash>.jwt
// The 4-character prefix directory reduces directory entry count for
// file systems that degrade at large directory sizes.
//
// Files older than TTL are treated as expired and return ErrNotFound.
// Expired files are lazily deleted on the next Get call.
type FilesystemStore struct {
	baseDir string
	ttl     time.Duration
}

// NewFilesystemStore creates a Tier-1 store rooted at baseDir with the given TTL.
// Pass 0 for ttl to use the default (48h).
// The base directory is created if it does not exist.
func NewFilesystemStore(baseDir string, ttl time.Duration) (*FilesystemStore, error) {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if err := os.MkdirAll(baseDir, dirPermission); err != nil {
		return nil, fmt.Errorf("store: failed to create base directory %q: %w", baseDir, err)
	}
	return &FilesystemStore{baseDir: baseDir, ttl: ttl}, nil
}

// Put writes a JWT to disk under its hash key.
func (f *FilesystemStore) Put(hash string, jwt string) error {
	path, err := f.hashPath(hash)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPermission); err != nil {
		return fmt.Errorf("store: mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(jwt), filePermission); err != nil {
		return fmt.Errorf("store: write: %w", err)
	}
	return nil
}

// Get retrieves a JWT by chain hash. Returns ErrNotFound if absent or expired.
// Expired files are deleted lazily.
func (f *FilesystemStore) Get(hash string) (string, error) {
	path, err := f.hashPath(hash)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("store: stat: %w", err)
	}

	// Lazy expiry check
	if time.Since(info.ModTime()) > f.ttl {
		_ = os.Remove(path) // best-effort deletion of stale entry
		return "", ErrNotFound
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("store: read: %w", err)
	}
	return string(data), nil
}

// Delete removes an entry from disk. No-ops if absent.
func (f *FilesystemStore) Delete(hash string) error {
	path, err := f.hashPath(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// hashPath maps a store key to an absolute file path.
// Strips the "sha256:" prefix and accepts an optional ".jwt" or ".tst"
// extension in the key (Tier3Store uses ".tst" for RFC 3161 timestamp tokens).
// Returns an error for any other shape — this is the path-traversal boundary,
// so it must be strict and fail-closed.
func (f *FilesystemStore) hashPath(hash string) (string, error) {
	name := strings.TrimPrefix(hash, "sha256:")
	m := validKeyRe.FindStringSubmatch(name)
	if m == nil {
		return "", fmt.Errorf("store: invalid key %q: must be 64 lowercase hex characters with an optional .jwt or .tst extension", hash)
	}
	digest := m[1]
	ext := m[2]
	if ext == "" {
		ext = "jwt"
	}
	prefix := digest[:4]
	return filepath.Join(f.baseDir, prefix, digest+"."+ext), nil
}
