package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTTL      = 48 * time.Hour
	filePermission  = 0o600
	dirPermission   = 0o700
	janitorInterval = 1 * time.Hour

	// NeverExpire is a sentinel TTL value passed to NewFilesystemStore to
	// disable expiry entirely. Suitable for Tier-1 forensic/evidence stores
	// where receipts must be retained indefinitely.
	NeverExpire time.Duration = -1
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
// When constructed with NeverExpire, neither lazy deletion nor sweeps
// will remove any entry.
type FilesystemStore struct {
	baseDir  string
	ttl      time.Duration
	noExpiry bool
}

// NewFilesystemStore creates a Tier-1 store rooted at baseDir with the given TTL.
//
// ttl == 0       → use the default TTL (48h).
// ttl < 0        → NeverExpire: entries are retained indefinitely; the janitor
//
//	is a no-op and lazy Get deletion is disabled.
//
// ttl > 0        → use that exact duration.
//
// The base directory is created if it does not exist.
func NewFilesystemStore(baseDir string, ttl time.Duration) (*FilesystemStore, error) {
	f := &FilesystemStore{baseDir: baseDir}
	switch {
	case ttl == 0:
		f.ttl = defaultTTL
	case ttl < 0:
		f.noExpiry = true
	default:
		f.ttl = ttl
	}
	if err := os.MkdirAll(baseDir, dirPermission); err != nil {
		return nil, fmt.Errorf("store: failed to create base directory %q: %w", baseDir, err)
	}
	return f, nil
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

	// Lazy expiry check — skipped for non-expiring stores.
	if !f.noExpiry && time.Since(info.ModTime()) > f.ttl {
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

// sweepExpired removes every store entry older than the TTL. It only touches
// files whose names match a store key (64-hex with .jwt/.tst), re-stats each
// file immediately before removal so a concurrent Put refresh is not clobbered,
// and is a no-op for a non-expiring store. Returns the number removed.
func (f *FilesystemStore) sweepExpired() (int, error) {
	if f.noExpiry {
		return 0, nil
	}
	removed := 0
	err := filepath.WalkDir(f.baseDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if validKeyRe.FindStringSubmatch(d.Name()) == nil {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || time.Since(info.ModTime()) <= f.ttl {
			return nil
		}
		// Re-stat before removal: a concurrent Put may have refreshed the file.
		if cur, err := os.Stat(path); err == nil && time.Since(cur.ModTime()) <= f.ttl {
			return nil
		}
		if os.Remove(path) == nil {
			removed++
		}
		return nil
	})
	return removed, err
}

// StartJanitor runs periodic sweeps until ctx is cancelled. No-op for a
// non-expiring store. Call only for ephemeral (Tier-1) stores.
func (f *FilesystemStore) StartJanitor(ctx context.Context) {
	f.startJanitor(ctx, janitorInterval)
}

func (f *FilesystemStore) startJanitor(ctx context.Context, interval time.Duration) {
	if f.noExpiry {
		slog.Info("store janitor not started: store is non-expiring")
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := f.sweepExpired(); err != nil {
					slog.Warn("store janitor: sweep error", "error", err)
				} else if n > 0 {
					slog.Info("store janitor: removed expired entries", "count", n)
				}
			}
		}
	}()
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
