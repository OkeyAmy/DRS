package revocation

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FileBackedRevocationStore persists revoked status list indices to an
// append-only text log on local disk. Each successful Revoke writes
// one decimal index per line, calls fsync, then updates the in-memory
// set. Startup reads the file once and populates the set.
//
// Durability contract: once Revoke returns nil, the revocation is on
// persistent storage, survives process restart, and is visible to any
// future IsRevoked call in this process.
//
// This store is appropriate when:
//   - you need emergency revocation that outlives a container restart
//   - you do not yet need cross-replica sharing (for that, use a remote
//     status list or a network-backed store in a future iteration)
//
// File format: UTF-8, one decimal uint64 per line. Empty lines and
// lines beginning with '#' are ignored. Unparseable lines are skipped
// with a warning, not a fatal error — allowing an operator to manually
// edit the file without taking the service down.
type FileBackedRevocationStore struct {
	// readMu guards the in-memory revoked set.
	readMu  sync.RWMutex
	revoked map[uint64]struct{}

	// writeMu serialises appends so writes to file are linear and
	// the in-memory set is updated in the same critical section.
	writeMu sync.Mutex
	path    string
	file    *os.File
}

// OpenFileBackedRevocationStore opens the store at path. If the file
// does not exist, it is created with mode 0600. Any existing content is
// loaded into memory; subsequent Revoke calls append.
//
// The parent directory is created with 0700 if missing — operators who
// want a custom path mode should pre-create the directory.
func OpenFileBackedRevocationStore(path string) (*FileBackedRevocationStore, error) {
	// Ensure parent directory exists.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("revocation: create store dir %q: %w", dir, err)
		}
	}

	s := &FileBackedRevocationStore{
		revoked: make(map[uint64]struct{}),
		path:    path,
	}

	if err := s.loadExisting(); err != nil {
		return nil, err
	}

	// Open for append, create if absent. O_APPEND + fsync is the usual
	// idiom for append-only durability.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("revocation: open append handle %q: %w", path, err)
	}
	s.file = f
	slog.Info("revocation store loaded", "path", path, "revoked_count", len(s.revoked))
	return s, nil
}

// loadExisting reads the file once at startup and populates the in-memory set.
// Missing files are treated as an empty store (not an error).
func (s *FileBackedRevocationStore) loadExisting() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("revocation: open existing store %q: %w", s.path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	// Allow generous line buffer — a malformed file shouldn't crash the scanner
	// but a 64KB line is well beyond a plausible uint64.
	const maxLine = 64 * 1024
	scanner.Buffer(make([]byte, 4096), maxLine)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			slog.Warn("revocation: skipping malformed line in store",
				"path", s.path, "line_no", lineNo, "content", line, "error", err)
			continue
		}
		s.revoked[idx] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("revocation: read store %q: %w", s.path, err)
	}
	return nil
}

// Revoke appends the index to the backing file, fsyncs, and updates the
// in-memory set. Returns an error if the write or fsync fails; callers
// (e.g. AdminRevokeHandler) must treat this as operation-failed and report
// 5xx rather than pretending the revoke succeeded.
//
// Revoking an already-revoked index writes a duplicate line (cheap) but the
// in-memory set remains a single entry. Duplicates are compacted on the next
// startup without operator intervention.
func (s *FileBackedRevocationStore) Revoke(index uint64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	line := strconv.FormatUint(index, 10) + "\n"
	if _, err := s.file.WriteString(line); err != nil {
		return fmt.Errorf("revocation: write index %d: %w", index, err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("revocation: fsync after index %d: %w", index, err)
	}

	s.readMu.Lock()
	s.revoked[index] = struct{}{}
	s.readMu.Unlock()
	return nil
}

// IsRevoked returns true if the index is in the in-memory set.
// Lookup does not touch the file.
func (s *FileBackedRevocationStore) IsRevoked(index uint64) bool {
	s.readMu.RLock()
	defer s.readMu.RUnlock()
	_, ok := s.revoked[index]
	return ok
}

// Close releases the file handle. Subsequent Revoke calls will fail.
// Safe to call multiple times; subsequent calls return the first error.
func (s *FileBackedRevocationStore) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
