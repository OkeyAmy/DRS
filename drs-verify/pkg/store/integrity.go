package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// IntegrityStore decorates a Store so reads are tamper-evident. Receipt keys
// are the SHA-256 of their value ("sha256:"+hex), so on Get we recompute the
// hash and reject any value that does not match its key. RFC 3161 timestamp
// tokens (".tst" keys) are not content-addressed by the key; their integrity
// is the TSA signature, verified downstream, so they pass through.
type IntegrityStore struct {
	inner Store
}

func NewIntegrityStore(inner Store) *IntegrityStore {
	return &IntegrityStore{inner: inner}
}

func (s *IntegrityStore) Put(hash, jwt string) error {
	return s.inner.Put(hash, jwt)
}

func (s *IntegrityStore) Get(hash string) (string, error) {
	v, err := s.inner.Get(hash)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(hash, ".tst") {
		return v, nil
	}
	sum := sha256.Sum256([]byte(v))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(want), []byte(hash)) != 1 {
		return "", ErrIntegrity
	}
	return v, nil
}

func (s *IntegrityStore) Delete(hash string) error {
	return s.inner.Delete(hash)
}
