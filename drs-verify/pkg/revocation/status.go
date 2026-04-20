// Package revocation implements the W3C Bitstring Status List cache.
//
// Concurrency design:
// - sync.RWMutex guards the cached bitstring: many readers, one writer
// - initMu serialises retryable first-fetch attempts (replaces sync.Once,
//   which permanently consumed the first-fetch slot on failure and produced
//   a fail-open path when the endpoint was briefly down at boot)
// - refreshMu serialises TTL-triggered refreshes to prevent cache stampedes
// - hasSnapshot tracks whether a valid snapshot has ever been successfully
//   fetched. IsRevoked fails closed when no snapshot exists and refresh fails.
//
// Block F of the verification algorithm is implemented here.
package revocation

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// fetchTimeout bounds how long a single status list refresh may run.
// Independent of the caller's context: request cancellation must not abort a
// cache write that other callers depend on, but refreshes must have their own
// deadline so a slow status list endpoint cannot hang verifications forever.
const fetchTimeout = 15 * time.Second

// StatusCache caches a remote Bitstring Status List with TTL-based refresh.
type StatusCache struct {
	mu          sync.RWMutex
	initMu      sync.Mutex // serialises retryable first-fetch attempts
	refreshMu   sync.Mutex // serialises TTL-triggered refreshes; prevents cache stampede
	bitstring   []byte
	fetchedAt   time.Time
	hasSnapshot bool // true once a successful fetch has published a snapshot
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
//
// Fail-closed guarantee: if no valid snapshot has ever been fetched, this
// returns an error rather than (false, nil). A transient status-list outage
// at boot must not silently let revoked receipts through.
//
// ctx is honoured for fast-fail on caller cancellation; refreshes themselves
// use their own context (see fetchTimeout) so a cancelled request cannot abort
// a cache write other callers depend on.
func (s *StatusCache) IsRevoked(ctx context.Context, statusListIndex uint64) (bool, error) {
	// Fast-fail on caller cancellation before doing any work.
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// Retryable first-fetch path: if no snapshot has ever been published,
	// drive a refresh. Unlike sync.Once, a failed attempt here does not
	// permanently consume the slot — the next call retries.
	if !s.snapshotPublished() {
		if err := s.ensureInitialSnapshot(); err != nil {
			return false, fmt.Errorf("revocation: no valid status list snapshot available: %w", err)
		}
	}

	// Check if TTL has expired; refresh if so.
	s.mu.RLock()
	expired := time.Since(s.fetchedAt) > s.ttl
	s.mu.RUnlock()

	if expired {
		// Acquire refreshMu so that at most one goroutine calls refresh() per TTL
		// expiry, preventing a cache stampede under concurrent load.
		s.refreshMu.Lock()
		// Re-check expiry after acquiring the lock: a concurrent goroutine may have
		// already refreshed while we were waiting, making another fetch unnecessary.
		s.mu.RLock()
		stillExpired := time.Since(s.fetchedAt) > s.ttl
		s.mu.RUnlock()
		if stillExpired {
			// Background refresh: use context.Background() — a cancelled request ctx
			// must not abort a cache write that other requests depend on.
			if err := s.refresh(context.Background()); err != nil {
				// Log the error but serve stale data rather than blocking verification.
				// A monitoring alert should fire on persistent fetch failures.
				// Safe because snapshotPublished() is true here — this is a stale-data
				// refresh, not a first-fetch.
				slog.Warn("status list refresh failed, serving stale data", "error", err)
			}
		}
		s.refreshMu.Unlock()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return getBit(s.bitstring, statusListIndex), nil
}

// Ready returns true if the status list has been successfully fetched at least once.
// Used by the /readyz health endpoint.
//
// Returns false after a failed WarmUp() so orchestrators (Kubernetes, Nomad, etc.)
// do not route traffic to a verifier whose revocation cache would fail-closed
// for every request.
func (s *StatusCache) Ready() bool {
	return s.snapshotPublished()
}

// WarmUp performs the initial status list fetch eagerly on startup.
// Call this during server initialization to prevent readiness deadlock
// in orchestrators that gate traffic on /readyz.
//
// Retryable: unlike the previous sync.Once-backed implementation, a failed
// WarmUp does not permanently disable future fetch attempts. Callers may
// re-invoke WarmUp (or simply let the first IsRevoked drive the init path)
// to recover when the status-list endpoint comes back.
func (s *StatusCache) WarmUp() error {
	return s.ensureInitialSnapshot()
}

// ensureInitialSnapshot drives the first-fetch path under initMu. If a
// concurrent caller has already successfully published a snapshot, this
// returns nil without fetching. On failure it returns the error without
// consuming the slot — callers may retry.
func (s *StatusCache) ensureInitialSnapshot() error {
	s.initMu.Lock()
	defer s.initMu.Unlock()

	if s.snapshotPublished() {
		return nil
	}
	return s.refresh(context.Background())
}

// snapshotPublished reports whether a successful refresh has ever committed
// a snapshot to the cache.
func (s *StatusCache) snapshotPublished() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasSnapshot
}

// refresh fetches the current status list from the remote endpoint.
// Only publishes the new bitstring if the entire body was read successfully.
// On failure, the previous known-good snapshot (if any) is preserved.
// Always enforces a fetchTimeout bound on the refresh regardless of ctx.
func (s *StatusCache) refresh(ctx context.Context) error {
	if s.baseURL == "" {
		// No remote status list configured — revocation is effectively disabled.
		// Mark as a valid snapshot so IsRevoked returns (false, nil) cleanly
		// instead of fail-closing on "no snapshot available".
		s.mu.Lock()
		s.bitstring = []byte{}
		s.fetchedAt = time.Now()
		s.hasSnapshot = true
		s.mu.Unlock()
		return nil
	}

	// Bound the refresh even when ctx is context.Background(). Without an
	// explicit deadline a slow TSA could block TTL-refresh goroutines forever.
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, s.baseURL, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", s.baseURL, err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", s.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP GET %s returned %d", s.baseURL, resp.StatusCode)
	}

	const maxStatusListBytes = 1 << 20 // 1 MiB
	limited := io.LimitReader(resp.Body, int64(maxStatusListBytes)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("status list from %s truncated or unreadable: %w", s.baseURL, err)
	}
	if len(buf) > maxStatusListBytes {
		return fmt.Errorf("status list from %s exceeds %d byte limit", s.baseURL, maxStatusListBytes)
	}
	if len(buf) == 0 {
		return fmt.Errorf("status list from %s is empty", s.baseURL)
	}

	// Reject truncated responses: if Content-Length is present and non-negative,
	// it must match the number of bytes received.
	if clStr := resp.Header.Get("Content-Length"); clStr != "" {
		cl, parseErr := strconv.ParseInt(clStr, 10, 64)
		if parseErr == nil && cl >= 0 && int64(len(buf)) != cl {
			return fmt.Errorf("status list from %s truncated: Content-Length %d, read %d bytes",
				s.baseURL, cl, len(buf))
		}
	}

	s.mu.Lock()
	s.bitstring = buf
	s.fetchedAt = time.Now()
	s.hasSnapshot = true
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
