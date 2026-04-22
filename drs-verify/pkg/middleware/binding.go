package middleware

import (
	"bytes"
	"encoding/json"
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

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// Body-read failure is not binding-specific; let the downstream handler
		// decide how to respond. Do not increment binding metrics for this case.
		return false
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
