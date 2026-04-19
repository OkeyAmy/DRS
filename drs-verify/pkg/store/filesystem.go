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

// validHashRe matches exactly 64 lowercase hex characters — a SHA-256 digest.
// Anything else (path separators, dots, uppercase, wrong length) is rejected.
var validHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

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

// hashPath maps a chain hash key to an absolute file path.
// Strips the "sha256:" prefix before using the hex digest as a filename.
// Returns an error if the hash is not exactly 64 lowercase hex characters.
func (f *FilesystemStore) hashPath(hash string) (string, error) {
	name := strings.TrimPrefix(hash, "sha256:")
	if !validHashRe.MatchString(name) {
		return "", fmt.Errorf("store: invalid hash %q: must be 64 lowercase hex characters", hash)
	}
	prefix := name[:4]
	return filepath.Join(f.baseDir, prefix, name+".jwt"), nil
}
