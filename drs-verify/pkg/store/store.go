// Package store defines the DR Store interface and implementations.
//
// Tiers (see docs/storage-tiers.md for the canonical reference):
//
//	0 — Session:     In-process memory (LRU), session lifetime only      [implemented]
//	1 — Ephemeral:   Local filesystem, 48h TTL                           [implemented]
//	2 — Durable:     S3-compatible object store                          [roadmap]
//	3 — Compliant:   WORM + RFC 3161 timestamp anchor, 7yr retention     [implemented: pkg/anchor/tier3store.go]
//	4 — Timestamped: Tier 3 + per-DR RFC 3161 TSToken                    [implemented: pkg/anchor/rfc3161.go]
//	5 — On-Chain:    Tier 3 + Ethereum mainnet hash anchor               [roadmap]
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
