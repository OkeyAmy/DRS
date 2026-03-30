package anchor_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/store"
)

// newTestMemory creates a MemoryStore for use in tests.
func newTestMemory(t *testing.T) *store.MemoryStore {
	t.Helper()
	s, err := store.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return s
}

// newTSAServer creates an httptest server that returns a minimal DER token with
// Content-Type application/timestamp-reply.
func newTSAServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeToken)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newFailingTSAServer creates an httptest server that always returns HTTP 500.
func newFailingTSAServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated TSA failure", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTier3Store_PutStoresJWTAndToken(t *testing.T) {
	inner := newTestMemory(t)
	tsaSrv := newTSAServer(t)

	ts := anchor.NewTier3Store(inner, anchor.NewTSAClient(tsaSrv.URL))

	const hash = "sha256:aabb00112233445566778899aabb00112233445566778899aabb001122334455"
	const jwt = "header.payload.sig"

	if err := ts.Put(hash, jwt); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// JWT must be present in the inner store.
	got, err := inner.Get(hash)
	if err != nil {
		t.Fatalf("inner.Get JWT: %v", err)
	}
	if got != jwt {
		t.Errorf("JWT: got %q, want %q", got, jwt)
	}

	// Timestamp token must be present under hash+".tst".
	tokenKey := hash + ".tst"
	gotToken, err := inner.Get(tokenKey)
	if err != nil {
		t.Fatalf("inner.Get token: %v", err)
	}
	if string(gotToken) != string(fakeToken) {
		t.Errorf("token mismatch: got %x, want %x", gotToken, fakeToken)
	}
}

func TestTier3Store_PutWithTSAFailureStillStoresJWT(t *testing.T) {
	inner := newTestMemory(t)
	tsaSrv := newFailingTSAServer(t)

	ts := anchor.NewTier3Store(inner, anchor.NewTSAClient(tsaSrv.URL))

	const hash = "sha256:ccdd00112233445566778899aabb00112233445566778899aabb001122334455"
	const jwt = "header.payload.sig"

	// Put must succeed even though TSA is unavailable.
	if err := ts.Put(hash, jwt); err != nil {
		t.Fatalf("Put with TSA failure returned error: %v", err)
	}

	// JWT must still be present in the inner store.
	got, err := inner.Get(hash)
	if err != nil {
		t.Fatalf("inner.Get after TSA failure: %v", err)
	}
	if got != jwt {
		t.Errorf("JWT: got %q, want %q", got, jwt)
	}

	// Token entry must be absent (TSA failed, nothing was stored).
	_, err = inner.Get(hash + ".tst")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token should be absent after TSA failure, got: %v", err)
	}
}

func TestTier3Store_GetDelegatesToInnerStore(t *testing.T) {
	inner := newTestMemory(t)
	tsaSrv := newTSAServer(t)

	ts := anchor.NewTier3Store(inner, anchor.NewTSAClient(tsaSrv.URL))

	const hash = "sha256:eeff00112233445566778899aabb00112233445566778899aabb001122334455"
	const jwt = "header.payload.sig"

	if err := inner.Put(hash, jwt); err != nil {
		t.Fatalf("inner.Put: %v", err)
	}

	got, err := ts.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != jwt {
		t.Errorf("Get: got %q, want %q", got, jwt)
	}

	// Get on missing key returns ErrNotFound.
	_, err = ts.Get("sha256:missing00112233445566778899aabb00112233445566778899aabb0011")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get on missing key: want ErrNotFound, got %v", err)
	}
}

func TestTier3Store_DeleteRemovesJWTAndToken(t *testing.T) {
	inner := newTestMemory(t)
	tsaSrv := newTSAServer(t)

	ts := anchor.NewTier3Store(inner, anchor.NewTSAClient(tsaSrv.URL))

	const hash = "sha256:1122334455aabb00112233445566778899aabb00112233445566778899aabb00"
	const jwt = "header.payload.sig"

	if err := ts.Put(hash, jwt); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := ts.Delete(hash); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// JWT must be gone.
	if _, err := inner.Get(hash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("JWT after Delete: want ErrNotFound, got %v", err)
	}

	// Token must be gone.
	if _, err := inner.Get(hash + ".tst"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token after Delete: want ErrNotFound, got %v", err)
	}
}
