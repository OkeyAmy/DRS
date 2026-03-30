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
