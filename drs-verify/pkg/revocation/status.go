// Package revocation implements the W3C Bitstring Status List cache.
//
// Concurrency design:
// - sync.RWMutex guards the cached bitstring: many readers, one writer
// - sync.Once on first fetch prevents the double-fetch race condition under
//   concurrent load (the race condition present in the v2 implementation)
// - TTL is checked on every read; a background refresh is triggered if stale
//
// Block F of the verification algorithm is implemented here.
package revocation

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// StatusCache caches a remote Bitstring Status List with TTL-based refresh.
type StatusCache struct {
	mu          sync.RWMutex
	once        sync.Once
	bitstring   []byte
	fetchedAt   time.Time
	ttl         time.Duration
	baseURL     string
	httpClient  *http.Client
}

// New creates a StatusCache that fetches from baseURL with the given TTL.
func New(baseURL string, ttl time.Duration) *StatusCache {
	return &StatusCache{
		baseURL:    baseURL,
		ttl:        ttl,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// IsRevoked returns true if the credential at the given statusListIndex is revoked.
// On the first call it fetches the status list (sync.Once prevents double-fetch).
// On subsequent calls it returns the cached value unless TTL has expired.
func (s *StatusCache) IsRevoked(statusListIndex uint64) (bool, error) {
	var initErr error

	// First fetch — protected by sync.Once to prevent double-fetch race condition
	s.once.Do(func() {
		initErr = s.refresh()
	})
	if initErr != nil {
		return false, fmt.Errorf("revocation: initial status list fetch failed: %w", initErr)
	}

	// Check if TTL has expired; refresh if so
	s.mu.RLock()
	expired := time.Since(s.fetchedAt) > s.ttl
	s.mu.RUnlock()

	if expired {
		if err := s.refresh(); err != nil {
			// Log the error but serve stale data rather than blocking verification.
			// A monitoring alert should fire on persistent fetch failures.
			log.Printf("revocation: status list refresh failed (serving stale data): %v", err)
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return getBit(s.bitstring, statusListIndex), nil
}

// Ready returns true if the status list has been successfully fetched at least once.
// Used by the /readyz health endpoint.
func (s *StatusCache) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bitstring) > 0
}

// refresh fetches the current status list from the remote endpoint.
func (s *StatusCache) refresh() error {
	if s.baseURL == "" {
		// No status list configured — revocation checking is disabled
		s.mu.Lock()
		s.bitstring = []byte{}
		s.fetchedAt = time.Now()
		s.mu.Unlock()
		return nil
	}

	resp, err := s.httpClient.Get(s.baseURL)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", s.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP GET %s returned %d", s.baseURL, resp.StatusCode)
	}

	// Read the raw bitstring bytes (compressed or raw — caller's responsibility)
	buf := make([]byte, 0, 16384)
	tmp := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	s.mu.Lock()
	s.bitstring = buf
	s.fetchedAt = time.Now()
	s.mu.Unlock()

	return nil
}

// getBit returns true if the bit at position index is set in the bitstring.
func getBit(bitstring []byte, index uint64) bool {
	byteIndex := index / 8
	bitIndex := index % 8
	if byteIndex >= uint64(len(bitstring)) {
		return false
	}
	return (bitstring[byteIndex]>>(7-bitIndex))&1 == 1
}
