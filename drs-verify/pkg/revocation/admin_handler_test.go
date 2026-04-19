package revocation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testAdminToken = "test-secret-token"

func TestAdminRevokeHandler_ValidRequest(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	body := `{"status_list_index":5}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp revokeResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if !resp.Revoked {
		t.Error("expected revoked:true in response body")
	}
	if resp.StatusListIndex != 5 {
		t.Errorf("expected status_list_index:5, got %d", resp.StatusListIndex)
	}
}

func TestAdminRevokeHandler_ValidRequest_StoreIsUpdated(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	body := `{"status_list_index":100}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !store.IsRevoked(100) {
		t.Error("expected store.IsRevoked(100) to return true after POST /admin/revoke")
	}
}

func TestAdminRevokeHandler_MalformedJSON(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected non-empty error field in 400 response")
	}
}

func TestAdminRevokeHandler_NonPostMethod(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(method, "/admin/revoke", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: expected 405 Method Not Allowed, got %d", method, rec.Code)
			}
		})
	}
}

func TestAdminRevokeHandler_MissingAuthToken_Returns401(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	body := `{"status_list_index":1}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
	// No Authorization header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Error != "unauthorized" {
		t.Errorf("expected error 'unauthorized', got %q", resp.Error)
	}
}

func TestAdminRevokeHandler_WrongAuthToken_Returns401(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	body := `{"status_list_index":1}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Error != "unauthorized" {
		t.Errorf("expected error 'unauthorized', got %q", resp.Error)
	}
}

func TestAdminRevokeHandler_EmptyToken_Returns503(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	// Empty token means admin endpoint is not configured
	handler := AdminRevokeHandler(store, "")

	body := `{"status_list_index":1}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable, got %d", rec.Code)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Error != "admin endpoint not configured — set DRS_ADMIN_TOKEN" {
		t.Errorf("unexpected error message: %q", resp.Error)
	}
}

func TestAdminRevokeHandler_OversizedBody_Returns400(t *testing.T) {
	t.Parallel()

	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, testAdminToken)

	// 2 KiB body — exceeds adminRevokeMaxBodyBytes (1 KiB)
	oversized := strings.Repeat("x", 2*1024)
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized body, got %d", rec.Code)
	}
}

func TestAdminRevokeTokenRejection(t *testing.T) {
	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, "correct-token-value")

	cases := []struct {
		name   string
		auth   string
		status int
	}{
		{"no auth header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-token-value", http.StatusUnauthorized},
		{"partial match prefix", "Bearer correct-token-valu", http.StatusUnauthorized},
		{"partial match suffix", "Bearer orrect-token-value", http.StatusUnauthorized},
		{"bearer missing", "correct-token-value", http.StatusUnauthorized},
		{"correct token", "Bearer correct-token-value", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"status_list_index":1}`
			req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Errorf("auth=%q: got status %d, want %d", tc.auth, w.Code, tc.status)
			}
		})
	}
}
