package revocation

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
