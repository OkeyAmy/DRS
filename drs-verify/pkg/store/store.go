// Package store defines the DR Store interface and implementations.
//
// Tiers:
//   0 — Memory: in-process LRU, ephemeral, fastest
//   1 — Filesystem: local disk, survives process restart, 48h TTL
//
// Higher tiers (S3, WORM, on-chain) are out of scope for this version.
package store

import "errors"

// ErrNotFound is returned when a DR hash has no corresponding entry.
var ErrNotFound = errors.New("store: DR not found")

// Store is the interface that all DR storage tiers implement.
// The key is always a SHA-256 chain hash in "sha256:{hex}" format.
// The value is the raw JWT string of the delegation receipt.
type Store interface {
	// Put stores a JWT under its chain hash key.
	// Overwrites silently if the key already exists.
	Put(hash string, jwt string) error

	// Get retrieves a JWT by its chain hash key.
	// Returns ErrNotFound if the key is absent or expired.
	Get(hash string) (string, error)

	// Delete removes a JWT entry. No-ops if absent.
	Delete(hash string) error
}
