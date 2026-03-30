// Package health provides /healthz and /readyz HTTP endpoints.
//
// /healthz — returns 200 OK always. Used by load balancers to confirm the
//            process is alive.
// /readyz  — returns 200 OK if the status list cache has been successfully
//            fetched at least once; 503 otherwise. Used by orchestrators
//            to gate traffic until the service is warm.
package health

import (
	"encoding/json"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/revocation"
)

// Handler returns an http.ServeMux with /healthz and /readyz registered.
func Handler(statusCache *revocation.StatusCache) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", liveness)
	mux.HandleFunc("/readyz", readiness(statusCache))
	return mux
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func readiness(cache *revocation.StatusCache) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cache == nil || cache.Ready() {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_ready", "reason": "status_list_not_fetched"})
	}
}
