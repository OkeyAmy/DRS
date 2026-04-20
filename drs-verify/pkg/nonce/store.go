// Package nonce provides a bounded, TTL-evicting store for invocation JTI
// deduplication. It prevents replay attacks by rejecting JTIs that have
// already been consumed within the TTL window.
package nonce

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrReplayDetected is returned when a JTI has already been consumed.
	ErrReplayDetected = errors.New("nonce replay detected: this invocation JTI has already been consumed")

	// ErrStoreExhausted is returned when the store is at capacity and no
	// expired entries can be evicted.
	ErrStoreExhausted = errors.New("nonce store at capacity with no expired entries to evict")
)

// Checker is the public contract for nonce stores. Middleware accepts a
// Checker so the deployment chooses the backend:
//
//   - *Store         — in-memory, single-process (this file)
//   - *RedisStore    — distributed, survives restart, shared across replicas (redis.go)
//
// Implementations MUST treat Check as atomic "claim-if-new": concurrent
// callers with the same jti must see exactly one success and the others
// ErrReplayDetected, regardless of whether they run in the same process.
type Checker interface {
	// Check claims the JTI. Returns nil for a new JTI (now recorded),
	// ErrReplayDetected if the JTI was already consumed within the TTL,
	// or ErrStoreExhausted if the backing store is at capacity.
	Check(jti string) error
}

// Store is a bounded, TTL-evicting in-memory nonce store.
// Safe for concurrent use.
type Store struct {
	mu         sync.Mutex
	seen       map[string]int64 // jti → unix timestamp of insertion
	maxEntries int
	ttl        time.Duration
	nowFunc    func() time.Time // injectable clock for testing
}

// New creates a nonce store with the given capacity and TTL.
func New(maxEntries int, ttl time.Duration) *Store {
	return &Store{
		seen:       make(map[string]int64, maxEntries),
		maxEntries: maxEntries,
		ttl:        ttl,
		nowFunc:    time.Now,
	}
}

// Check atomically verifies that jti has not been seen within the TTL window
// and records it. Returns nil if the jti is new, ErrReplayDetected if already
// consumed, or ErrStoreExhausted if at capacity with no expired entries.
func (s *Store) Check(jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc().Unix()
	ttlSecs := int64(s.ttl.Seconds())

	// Check if already seen and not expired.
	if insertedAt, ok := s.seen[jti]; ok {
		if now-insertedAt < ttlSecs {
			return ErrReplayDetected
		}
		// Expired — remove and allow re-use.
		delete(s.seen, jti)
	}

	// Evict expired entries if at capacity.
	if len(s.seen) >= s.maxEntries {
		for k, v := range s.seen {
			if now-v >= ttlSecs {
				delete(s.seen, k)
			}
		}
	}

	// Still at capacity after eviction — reject.
	if len(s.seen) >= s.maxEntries {
		return ErrStoreExhausted
	}

	s.seen[jti] = now
	return nil
}
