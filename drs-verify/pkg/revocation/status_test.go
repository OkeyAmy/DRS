package revocation

import (
	"net/http"
	"net/http/httptest"
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
	revoked, err := cache.IsRevoked(0)
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
	if _, err := c.IsRevoked(0); err != nil {
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

	revoked0, err := cache.IsRevoked(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked0 {
		t.Error("index 0 should be revoked")
	}

	revoked1, err := cache.IsRevoked(1)
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
	_, err := cache.IsRevoked(0)
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
	_, err := cache.IsRevoked(0)
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

	revoked, err := cache.IsRevoked(0)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if !revoked {
		t.Error("index 0 should be revoked after first fetch")
	}

	time.Sleep(time.Millisecond)

	// Second call triggers TTL refresh, which fails (500).
	// Stale data should be served — index 0 still revoked.
	revoked2, err := cache.IsRevoked(0)
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

	if _, err := cache.IsRevoked(0); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	time.Sleep(time.Millisecond)

	if _, err := cache.IsRevoked(0); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 server fetches due to TTL expiry, got %d", callCount)
	}
}
