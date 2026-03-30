package anchor_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
)

// fakeToken is a small DER-like byte slice used as a mock TSA response.
var fakeToken = []byte{0x30, 0x03, 0x02, 0x01, 0x00}

func TestTSAClient_ValidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeToken)
	}))
	defer srv.Close()

	client := anchor.NewTSAClient(srv.URL)
	token, err := client.Timestamp([]byte("test-hash-bytes"))
	if err != nil {
		t.Fatalf("Timestamp: unexpected error: %v", err)
	}
	if string(token) != string(fakeToken) {
		t.Errorf("token mismatch: got %x, want %x", token, fakeToken)
	}
}

func TestTSAClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := anchor.NewTSAClient(srv.URL)
	_, err := client.Timestamp([]byte("test-hash"))
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention HTTP 500: %v", err)
	}
}

func TestTSAClient_WrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeToken)
	}))
	defer srv.Close()

	client := anchor.NewTSAClient(srv.URL)
	_, err := client.Timestamp([]byte("test-hash"))
	if err == nil {
		t.Fatal("expected error for wrong Content-Type, got nil")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error should mention Content-Type: %v", err)
	}
}

func TestTSAClient_ResponseTooLarge(t *testing.T) {
	// Build a response body that exceeds 64 KiB.
	large := make([]byte, 64*1024+1)
	for i := range large {
		large[i] = 0xFF
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(large)
	}))
	defer srv.Close()

	client := anchor.NewTSAClient(srv.URL)
	_, err := client.Timestamp([]byte("test-hash"))
	if err == nil {
		t.Fatal("expected error for oversized response, got nil")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error should mention size limit: %v", err)
	}
}
