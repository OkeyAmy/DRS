package revocation

import (
	"sync"
	"testing"
)

func TestLocalRevocationStore_RevokedIndexIsRevoked(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	store.Revoke(42)

	if !store.IsRevoked(42) {
		t.Error("expected index 42 to be revoked after Revoke(42)")
	}
}

func TestLocalRevocationStore_UnrevokedIndexIsNotRevoked(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()

	if store.IsRevoked(99) {
		t.Error("expected index 99 to not be revoked on a fresh store")
	}
}

func TestLocalRevocationStore_RevokeIsSameIdempotent(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	store.Revoke(7)
	store.Revoke(7)
	store.Revoke(7)

	if !store.IsRevoked(7) {
		t.Error("expected index 7 to be revoked after multiple Revoke calls")
	}
}

func TestLocalRevocationStore_RevokeDoesNotAffectOtherIndices(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	store.Revoke(1)

	if store.IsRevoked(2) {
		t.Error("revoking index 1 must not affect index 2")
	}
}

// TestLocalRevocationStore_ConcurrentRevokeAndIsRevoked verifies that concurrent
// Revoke and IsRevoked calls are race-free and that all revoked indices are
// actually marked revoked after all goroutines have finished.
// Run with: go test -race ./...
func TestLocalRevocationStore_ConcurrentRevokeAndIsRevoked(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	const goroutines = 50
	const indexBound = 20

	// Record which indices will be passed to Revoke before spawning goroutines.
	revokedIndices := make([]uint64, goroutines)
	for i := 0; i < goroutines; i++ {
		revokedIndices[i] = uint64(i % indexBound)
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines revoke indices; the other half read them.
	for i := 0; i < goroutines; i++ {
		index := revokedIndices[i]
		go func(idx uint64) {
			defer wg.Done()
			store.Revoke(idx)
		}(index)
		go func(idx uint64) {
			defer wg.Done()
			_ = store.IsRevoked(idx)
		}(index)
	}

	wg.Wait()

	// Every index that was passed to Revoke must now be revoked.
	for _, idx := range revokedIndices {
		if !store.IsRevoked(idx) {
			t.Errorf("expected index %d to be revoked after all goroutines finished, but IsRevoked returned false", idx)
		}
	}
}
