package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
)

type contextKey struct{}

var errBodyTooLarge = errors.New("request body exceeds 64 KiB")

// VerificationContext returns the context attached to an allowed, gated request.
func VerificationContext(ctx context.Context) *types.VerificationContext {
	v, _ := ctx.Value(contextKey{}).(*types.VerificationContext)
	return v
}

// Middleware enforces DRS on next using adapter a. The request body is read
// (capped at MaxBodyBytes) and restored for next.
func Middleware(cfg Config, a Adapter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readCapped(w, r)
		if err != nil {
			d := deny(http.StatusBadRequest, "BODY_READ_ERROR", "request body could not be read", "")
			if errors.Is(err, errBodyTooLarge) {
				d = deny(http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", err.Error(), "")
			}
			status, out := a.Reject(nil, d)
			write(w, status, out)
			return
		}
		d := Decide(r.Context(), cfg, a, Inbound{Method: r.Method, Header: r.Header, Body: body})
		if !d.Allow {
			write(w, d.Status, d.Body)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if d.Context != nil {
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, d.Context))
		}
		next.ServeHTTP(w, r)
	})
}

// forwardedHeaders are the only request headers /v1/gate consults. Credentials
// (Authorization, Cookie) are never needed and never accepted.
var forwardedHeaders = []string{BundleHeader, "Mcp-Method", "Mcp-Name", "Mcp-Protocol-Version", "A2a-Version", "A2a-Extensions"}

// GateRequest is the /v1/gate request body.
type GateRequest struct {
	Protocol string            `json:"protocol"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Body     json.RawMessage   `json:"body"`
}

// Handler serves POST /v1/gate: an out-of-process enforcement point (a Node
// or Python tool server) forwards the protocol request and receives a
// Decision. Every protocol rule lives here, so gates in other languages hold
// none.
func Handler(cfg Config, maxRequestBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		var req GateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_GATE_REQUEST", "detail": err.Error()})
			return
		}
		a, ok := AdapterFor(req.Protocol)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "UNKNOWN_PROTOCOL", "detail": "protocol must be http, mcp, or a2a"})
			return
		}
		if len(req.Body) > MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "BODY_TOO_LARGE"})
			return
		}
		h := http.Header{}
		for _, name := range forwardedHeaders {
			for k, v := range req.Headers {
				if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(name) {
					h.Add(name, v)
				}
			}
		}
		body := []byte(req.Body)
		if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
			body = nil
		}
		d := Decide(r.Context(), cfg, a, Inbound{Method: req.Method, Header: h, Body: body})
		writeJSON(w, http.StatusOK, d)
	})
}

func readCapped(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return nil, errBodyTooLarge
	}
	return body, err
}

func write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	body, _ := json.Marshal(v)
	write(w, status, body)
}
