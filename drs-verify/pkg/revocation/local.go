package revocation

import "sync"

// LocalRevocationStore is a thread-safe in-memory set that records locally
// revoked delegation receipt status list indices.
//
// It is checked alongside the remote StatusCache during Block F verification.
// Revocations applied here take effect immediately on the next verification call
// without any network round-trip.
//
// Persistence: in-memory only — does not survive a process restart. Use
// FileBackedRevocationStore when durability across restart is required.
type LocalRevocationStore struct {
	mu      sync.RWMutex
	revoked map[uint64]struct{}
}

// NewLocalRevocationStore returns an empty, ready-to-use LocalRevocationStore.
func NewLocalRevocationStore() *LocalRevocationStore {
	return &LocalRevocationStore{
		revoked: make(map[uint64]struct{}),
	}
}

// Revoke marks the given status list index as revoked.
// Idempotent; always returns nil (in-memory stores cannot fail).
// Signature matches LocalStore so callers can swap for the file-backed variant.
func (s *LocalRevocationStore) Revoke(index uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[index] = struct{}{}
	return nil
}

// IsRevoked returns true if the given status list index has been revoked.
func (s *LocalRevocationStore) IsRevoked(index uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[index]
	return ok
}
