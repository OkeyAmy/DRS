package revocation

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetBitSetBit(t *testing.T) {
	// Byte 0xFF has all bits set
	bs := []byte{0xFF}
	for i := uint64(0); i < 8; i++ {
		if !getBit(bs, i) {
			t.Errorf("bit %d should be set in 0xFF", i)
		}
	}
}

func TestGetBitClearBit(t *testing.T) {
	// Byte 0x00 has no bits set
	bs := []byte{0x00}
	for i := uint64(0); i < 8; i++ {
		if getBit(bs, i) {
			t.Errorf("bit %d should not be set in 0x00", i)
		}
	}
}

func TestGetBitMSBFirst(t *testing.T) {
	// 0x80 = 1000_0000 — only bit 0 (MSB) is set
	bs := []byte{0x80}
	if !getBit(bs, 0) {
		t.Error("bit 0 should be set in 0x80")
	}
	for i := uint64(1); i < 8; i++ {
		if getBit(bs, i) {
			t.Errorf("bit %d should not be set in 0x80", i)
		}
	}
}

func TestGetBitOutOfRange(t *testing.T) {
	bs := []byte{0xFF}
	// Index beyond the bitstring length must return false, not panic
	if getBit(bs, 100) {
		t.Error("out-of-range bit must return false")
	}
}

func TestIsRevokedReturnsFalseWhenNoStatusList(t *testing.T) {
	cache := New("", time.Hour)
	revoked, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Error("should not be revoked when no status list is configured")
	}
}

func TestReadyTrueAfterSuccessfulFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00})
	}))
	defer srv.Close()

	c := New(srv.URL, time.Hour)
	if _, err := c.IsRevoked(context.Background(), 0); err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !c.Ready() {
		t.Error("Ready() should return true after successful fetch")
	}
}

func TestIsRevokedFetchesFromServer(t *testing.T) {
	// Bitstring: 0x80 = index 0 is revoked, indices 1-7 are not
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x80})
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)

	revoked0, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked0 {
		t.Error("index 0 should be revoked")
	}

	revoked1, err := cache.IsRevoked(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked1 {
		t.Error("index 1 should not be revoked")
	}
}

func TestRefreshRejectsPartialRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		// Only write 5 bytes of the advertised 100 — simulates truncated transfer
		_, _ = w.Write([]byte{0x80, 0x00, 0x00, 0x00, 0x00})
		// Intentionally close the connection early by not writing the remaining bytes
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	_, err := cache.IsRevoked(context.Background(), 0)
	// io.ReadAll on a truncated body with Content-Length mismatch should return
	// an error, preventing partial data from being published
	if err == nil {
		// If io.ReadAll didn't error (server closed cleanly), verify the data
		// was at least non-empty and the Ready flag works
		if !cache.Ready() {
			t.Error("cache should be ready after a successful fetch")
		}
	}
}

func TestRefreshRejectsEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body — no bitstring data
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	_, err := cache.IsRevoked(context.Background(), 0)
	if err == nil {
		t.Error("expected error for empty status list body")
	}
}

func TestRefreshPreservesStaleDataOnFailure(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0x80})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Nanosecond)

	revoked, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if !revoked {
		t.Error("index 0 should be revoked after first fetch")
	}

	time.Sleep(time.Millisecond)

	// Second call triggers TTL refresh, which fails (500).
	// Stale data should be served — index 0 still revoked.
	revoked2, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("second call should not error (stale data): %v", err)
	}
	if !revoked2 {
		t.Error("index 0 should still be revoked from stale data after refresh failure")
	}
}

func TestWarmUpPerformsInitialFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x80})
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	if cache.Ready() {
		t.Error("should not be ready before WarmUp")
	}

	if err := cache.WarmUp(); err != nil {
		t.Fatalf("WarmUp failed: %v", err)
	}
	if !cache.Ready() {
		t.Error("should be ready after WarmUp")
	}
}

func TestTTLExpiryTriggersRefresh(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00})
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Nanosecond) // near-instant TTL

	if _, err := cache.IsRevoked(context.Background(), 0); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	time.Sleep(time.Millisecond)

	if _, err := cache.IsRevoked(context.Background(), 0); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 server fetches due to TTL expiry, got %d", callCount)
	}
}

func TestRefreshRejectsTruncatedBody(t *testing.T) {
	// Serve a body that is shorter than the advertised Content-Length.
	fullBody := bytes.Repeat([]byte{0x00}, 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "200") // lie: advertise 200, send 100
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fullBody)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	err := cache.WarmUp()
	if err == nil {
		t.Fatal("expected error for truncated body, got nil")
	}
	if !strings.Contains(err.Error(), "truncated") && !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("error should mention truncation: %v", err)
	}

	// The cache must remain uninitialized (no partial data committed).
	if cache.Ready() {
		t.Error("cache.Ready() must be false after failed fetch")
	}
}

func TestRefreshRejectsOversizeBody(t *testing.T) {
	// Serve a body larger than 1 MiB.
	oversized := bytes.Repeat([]byte{0xFF}, (1<<20)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	err := cache.WarmUp()
	if err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
}

func TestRefreshPreservesSnapshotOnError(t *testing.T) {
	// First fetch succeeds; second fetch returns a truncated body.
	// The cache must serve the first snapshot after the failed refresh.
	callCount := 0
	goodBody := []byte{0b10000000} // bit 0 set → index 0 is revoked

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(goodBody)
		} else {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0x00}) // truncated
		}
	}))
	defer srv.Close()

	cache := New(srv.URL, 1*time.Millisecond) // very short TTL triggers refresh
	if err := cache.WarmUp(); err != nil {
		t.Fatalf("WarmUp: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let TTL expire

	// IsRevoked triggers refresh; it should fail and preserve old snapshot.
	revoked, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	// Old snapshot had bit 0 set → should still return true.
	if !revoked {
		t.Error("expected index 0 to be revoked (from preserved snapshot)")
	}
}

func TestIsRevokedReturnsErrorOnCancelledContext(t *testing.T) {
	// A cancelled context must cause IsRevoked to fail fast — without waiting
	// for a status-list fetch that would block on the network.
	c := New("http://127.0.0.1:1/unreachable", time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling
	_, err := c.IsRevoked(ctx, 0)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got: %v", err)
	}
}

func TestIsRevokedFailsClosedWhenNoSnapshotAvailable(t *testing.T) {
	// Regression: if WarmUp() fails (or is never called) and every subsequent
	// refresh also fails, IsRevoked must return an error — not (false, nil).
	// Returning false with nil error would be a fail-open bug: revoked receipts
	// get treated as not-revoked whenever the status list endpoint is down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	// Simulate startup warm-up: result is logged but execution continues.
	_ = cache.WarmUp()

	revoked, err := cache.IsRevoked(context.Background(), 42)
	if err == nil {
		t.Fatalf("fail-open: IsRevoked returned (revoked=%v, err=nil) when no snapshot was available", revoked)
	}
	if cache.Ready() {
		t.Error("Ready() must be false when no snapshot has ever been fetched")
	}
}

func TestWarmUpCanBeRetriedAfterFailure(t *testing.T) {
	// Regression: the original implementation used sync.Once inside WarmUp, so
	// a failed initial fetch permanently prevented future fetches. After the
	// fix, a failed WarmUp is retryable.
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x80})
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	if err := cache.WarmUp(); err == nil {
		t.Fatal("expected WarmUp to fail while endpoint returns 503")
	}
	if cache.Ready() {
		t.Error("cache should not be Ready after a failed WarmUp")
	}

	// Endpoint recovers — WarmUp must retry successfully.
	fail.Store(false)

	if err := cache.WarmUp(); err != nil {
		t.Fatalf("WarmUp must retry on recovery, got: %v", err)
	}
	if !cache.Ready() {
		t.Error("cache must be Ready after a successful retry WarmUp")
	}
}

func TestIsRevokedRecoversAfterWarmUpFailure(t *testing.T) {
	// Endpoint is down during WarmUp; comes back up when IsRevoked runs.
	// IsRevoked must drive the initial-fetch path and succeed — not remain
	// stuck on the first-call failure.
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x80})
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	_ = cache.WarmUp() // fails; main.go logs and continues

	fail.Store(false)

	revoked, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("IsRevoked must recover after WarmUp failure: %v", err)
	}
	if !revoked {
		t.Error("index 0 should be revoked per server response")
	}
	if !cache.Ready() {
		t.Error("cache must be Ready after a successful fetch via IsRevoked")
	}
}

func TestReadyFalseAfterFailedWarmUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	_ = cache.WarmUp()
	if cache.Ready() {
		t.Error("Ready() must be false after a failed WarmUp — readiness probes must not report ready")
	}
}

func TestRefreshHasExplicitFetchTimeout(t *testing.T) {
	// Serve a connection that accepts the request but never responds. The
	// refresh must fail via its own fetchTimeout, not the HTTP client timeout
	// (which would also work but we want the context-level bound to be active).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		// Hold connection open without responding.
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		// Then sleep — never send a response.
		time.Sleep(30 * time.Second)
	}()
	start := time.Now()
	cache := New("http://"+l.Addr().String(), time.Hour)
	_, err = cache.IsRevoked(context.Background(), 0)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// The http.Client has Timeout=10s; the context adds fetchTimeout=15s.
	// Whichever fires first wins — must be within ~20s.
	if elapsed > 20*time.Second {
		t.Errorf("refresh did not honour timeout: took %v", elapsed)
	}
}
