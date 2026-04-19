package anchor

import (
	"crypto/sha256"
	"log/slog"

	"github.com/drs-protocol/drs-verify/pkg/store"
)

// Tier3Store wraps a store.Store and anchors each stored JWT with an RFC 3161
// timestamp token. The token is written to a sibling entry alongside the JWT.
//
// Layout: the timestamp token is stored under the key hash+".tst".
// For FilesystemStore backends this maps to a sibling file with a .tst extension.
// For other store backends the key hash+".tst" is used directly.
type Tier3Store struct {
	inner store.Store
	tsa   *TSAClient
}

// NewTier3Store creates a Tier3Store that wraps inner and anchors every stored
// JWT with a timestamp from tsa.
func NewTier3Store(inner store.Store, tsa *TSAClient) *Tier3Store {
	return &Tier3Store{inner: inner, tsa: tsa}
}

// Put stores the JWT in the inner store, then requests an RFC 3161 timestamp
// for it and stores that token under hash+".tst".
//
// TSA failure is non-fatal: if the timestamp request fails, Put logs the error
// and returns nil. The JWT is always stored regardless of TSA availability.
func (t *Tier3Store) Put(hash string, jwt string) error {
	if err := t.inner.Put(hash, jwt); err != nil {
		return err
	}

	digest := sha256.Sum256([]byte(jwt))
	token, err := t.tsa.Timestamp(digest[:])
	if err != nil {
		slog.Warn("tier3: TSA timestamp failed", "hash", hash, "error", err)
		return nil
	}

	tokenKey := hash + ".tst"
	if err := t.inner.Put(tokenKey, string(token)); err != nil {
		slog.Warn("tier3: failed to store timestamp token", "hash", hash, "error", err)
	}
	return nil
}

// Get retrieves a JWT by its chain hash key. Delegates directly to the inner store.
func (t *Tier3Store) Get(hash string) (string, error) {
	return t.inner.Get(hash)
}

// Delete removes the JWT and its associated timestamp token.
// A missing token entry is silently ignored. An error deleting the token is
// logged but does not prevent the JWT deletion from being reported as successful.
func (t *Tier3Store) Delete(hash string) error {
	if err := t.inner.Delete(hash); err != nil {
		return err
	}

	tokenKey := hash + ".tst"
	if err := t.inner.Delete(tokenKey); err != nil {
		slog.Warn("tier3: failed to delete timestamp token", "hash", hash, "error", err)
	}
	return nil
}
