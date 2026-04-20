package revocation

// LocalStore is the contract every local revocation backend implements.
//
// Local revocation is the immediate, operator-triggered path — distinct from
// the remote W3C Bitstring Status List which is polled on a cache TTL. Two
// backends live in this package:
//
//   - LocalRevocationStore       — in-memory, fastest, loses state on restart
//   - FileBackedRevocationStore  — append-only log on disk, durable across restart
//
// Revoke returns an error so persistence failures propagate to the admin
// endpoint. An operator who calls POST /admin/revoke must know whether the
// change survived a crash — returning 200 on a failed fsync would be a
// silent-correctness bug.
type LocalStore interface {
	// Revoke marks the given status list index as revoked.
	// Idempotent: re-revoking an already-revoked index is a no-op.
	// Returns non-nil only when the backend failed to durably persist the
	// change (file I/O error, disk full, etc.) — in that case the in-memory
	// state may or may not reflect the revocation; callers must treat the
	// operation as failed.
	Revoke(index uint64) error

	// IsRevoked returns true if the given status list index has been revoked.
	// Never returns an error: lookups are in-memory after startup load.
	IsRevoked(index uint64) bool
}
