package store

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultMemoryCapacity = 10_000

// MemoryStore is a Tier-0 in-process LRU DR store.
// It is bounded by maxEntries to prevent unbounded growth under agent churn.
// All operations are safe for concurrent use.
type MemoryStore struct {
	mu    sync.RWMutex
	cache *lru.Cache[string, string]
}

// NewMemoryStore creates a Tier-0 store capped at maxEntries JWTs.
// Pass 0 to use the default cap (10 000 entries).
func NewMemoryStore(maxEntries int) (*MemoryStore, error) {
	if maxEntries <= 0 {
		maxEntries = defaultMemoryCapacity
	}
	c, err := lru.New[string, string](maxEntries)
	if err != nil {
		return nil, err
	}
	return &MemoryStore{cache: c}, nil
}

// Put stores a JWT under its chain hash key.
func (m *MemoryStore) Put(hash string, jwt string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache.Add(hash, jwt)
	return nil
}

// Get retrieves a JWT by chain hash. Returns ErrNotFound if absent.
func (m *MemoryStore) Get(hash string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.cache.Get(hash)
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Delete removes an entry. No-ops if absent.
func (m *MemoryStore) Delete(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache.Remove(hash)
	return nil
}
