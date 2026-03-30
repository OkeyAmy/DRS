package revocation

import (
	"encoding/json"
	"log"
	"net/http"
)

const adminRevokeMaxBodyBytes = 1024 // 1 KiB

// revokeRequest is the JSON body for POST /admin/revoke.
type revokeRequest struct {
	StatusListIndex uint64 `json:"status_list_index"`
}

// revokeResponse is the JSON body returned on a successful POST /admin/revoke.
type revokeResponse struct {
	Revoked         bool   `json:"revoked"`
	StatusListIndex uint64 `json:"status_list_index"`
}

// errorResponse is the JSON body returned on a failed POST /admin/revoke.
type errorResponse struct {
	Error string `json:"error"`
}

// AdminRevokeHandler returns an http.Handler for POST /admin/revoke.
//
// token is the expected bearer token. If empty, the endpoint responds 503
// (admin endpoint not configured). If non-empty, every request must carry
// an Authorization header matching "Bearer <token>" or it receives 401.
//
// Accepted body: {"status_list_index": N}
//
// Success (200):    {"revoked":true,"status_list_index":N}
// Bad JSON (400):   {"error":"..."}
// Unauthorized (401): {"error":"unauthorized"}
// Not configured (503): {"error":"admin endpoint not configured — set DRS_ADMIN_TOKEN"}
// Wrong method (405): no body
func AdminRevokeHandler(store *LocalRevocationStore, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if token == "" {
			writeJSON(w, http.StatusServiceUnavailable,
				errorResponse{Error: "admin endpoint not configured — set DRS_ADMIN_TOKEN"})
			return
		}

		if r.Header.Get("Authorization") != "Bearer "+token {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, adminRevokeMaxBodyBytes)

		var req revokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}

		store.Revoke(req.StatusListIndex)

		writeJSON(w, http.StatusOK, revokeResponse{
			Revoked:         true,
			StatusListIndex: req.StatusListIndex,
		})
	})
}

// writeJSON serialises v as JSON and writes it to w with the given status code.
// Content-Type is always set to application/json.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("admin_handler: encode response: %v", err)
	}
}
