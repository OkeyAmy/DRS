package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/binding"
	"github.com/drs-protocol/drs-verify/pkg/metrics"
)

// Binding-mode values. Must match the DRS_BINDING_MODE env var values parsed
// in pkg/config.
const (
	BindingModeOff      = "off"
	BindingModeLenient  = "lenient"
	BindingModeEnforced = "enforced"
	maxBindingBodyBytes = 65_536 // 64 KiB — largest legitimate tool-call body
)

// checkRequestBinding reads r.Body, compares it with the invocation's args via
// RFC 8785 JCS, and either aborts (enforced) or logs + emits a metric (lenient)
// on mismatch. Body is always restored on r so downstream handlers can read it.
//
// Returns true if the caller should abort (response already written);
// false to proceed.
func checkRequestBinding(w http.ResponseWriter, r *http.Request, invocationJWT, mode string) bool {
	if mode == BindingModeOff {
		metrics.BindingChecks.WithLabelValues("off").Inc()
		return false
	}

	// http.MaxBytesReader caps allocation AND closes the connection on overrun,
	// preventing slow-drip goroutine exhaustion. io.LimitReader caps bytes but
	// keeps the connection open; MaxBytesReader is the correct defense here.
	r.Body = http.MaxBytesReader(w, r.Body, maxBindingBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			metrics.BindingChecks.WithLabelValues("body_too_large").Inc()
			slog.Warn("binding: request body exceeds maximum", "max_bytes", maxBindingBodyBytes)
			writeBindingError(w, http.StatusRequestEntityTooLarge, "BINDING_BODY_TOO_LARGE",
				fmt.Sprintf("request body exceeds %d bytes", maxBindingBodyBytes),
				"Reduce the request body size or raise MAX_BODY_BYTES for the verifier entrypoint.")
			return true
		}
		metrics.BindingChecks.WithLabelValues("read_error").Inc()
		// Full error is logged server-side; the client receives a stable,
		// generic message so OS/network error strings (internal IPs, ports)
		// are not echoed back as reconnaissance data.
		slog.Warn("binding: cannot read request body", "error", err)
		writeBindingError(w, http.StatusBadRequest, "BINDING_BODY_READ_ERROR",
			"request body could not be read",
			"Ensure the request body can be read before DRS binding verification.")
		return true
	}
	// Always restore the body so the next handler can read it, regardless of outcome.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	args, err := DecodeInvocationArgs(invocationJWT)
	if err != nil {
		metrics.BindingChecks.WithLabelValues("invalid_body").Inc()
		slog.Warn("binding: cannot decode invocation args", "error", err)
		if mode == BindingModeEnforced {
			writeBindingError(w, http.StatusBadRequest, "BINDING_INVALID_INVOCATION",
				err.Error(),
				"Ensure the invocation JWT includes a decodable payload.")
			return true
		}
		return false
	}

	if checkErr := binding.Check(bodyBytes, args); checkErr != nil {
		if mode == BindingModeEnforced {
			metrics.BindingChecks.WithLabelValues("mismatch_enforced").Inc()
			slog.Warn("binding mismatch — rejecting request", "error", checkErr)
			writeBindingError(w, http.StatusForbidden, "BINDING_MISMATCH",
				checkErr.Error(),
				"The request body must equal invocation.args after JCS canonicalisation.")
			return true
		}
		metrics.BindingChecks.WithLabelValues("mismatch_lenient").Inc()
		slog.Warn("binding mismatch (lenient mode — passing through)", "error", checkErr)
		return false
	}

	if len(bytes.TrimSpace(bodyBytes)) == 0 && binding.IsEmptyArgs(args) {
		metrics.BindingChecks.WithLabelValues("empty_match").Inc()
	} else {
		metrics.BindingChecks.WithLabelValues("match").Inc()
	}
	return false
}

func writeBindingError(w http.ResponseWriter, status int, code, detail, suggestion string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      code,
		"detail":     detail,
		"suggestion": suggestion,
	})
}
