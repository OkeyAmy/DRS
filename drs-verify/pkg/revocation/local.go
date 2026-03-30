package revocation

import "sync"

// LocalRevocationStore is a thread-safe in-memory set that records locally
// revoked delegation receipt status list indices.
//
// It is checked alongside the remote StatusCache during Block F verification.
// Revocations applied here take effect immediately on the next verification call
// without any network round-trip.
//
// Persistence note: this store is in-memory only and does not survive a process
// restart. Filesystem or database persistence is a Tier 2 roadmap item.
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
// Calling Revoke on an already-revoked index is safe and idempotent.
func (s *LocalRevocationStore) Revoke(index uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[index] = struct{}{}
}

// IsRevoked returns true if the given status list index has been revoked.
func (s *LocalRevocationStore) IsRevoked(index uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[index]
	return ok
}
