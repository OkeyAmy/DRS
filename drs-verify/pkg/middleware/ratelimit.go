package middleware

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const (
	// ipLimiterCacheSize is the maximum number of per-IP limiters kept in memory.
	// At ~200 bytes per limiter, 10 000 entries ≈ 2 MB.
	ipLimiterCacheSize = 10_000
)

// RateLimiter enforces per-IP and global request rate limits.
type RateLimiter struct {
	global     *rate.Limiter
	perIPMu    sync.Mutex
	perIP      *lru.Cache[string, *rate.Limiter]
	perIPRate  rate.Limit
	trustProxy bool
}

// NewRateLimiter creates a RateLimiter with per-IP and global token buckets.
// perIPRPS and globalRPS are sustained requests per second; burst is set equal
// to the per-IP rate (minimum 1) for the per-IP limiter, and 2× for global.
// trustProxy controls whether X-Forwarded-For is trusted for IP extraction.
func NewRateLimiter(perIPRPS, globalRPS float64, trustProxy bool) *RateLimiter {
	cache, _ := lru.New[string, *rate.Limiter](ipLimiterCacheSize)
	burst := int(perIPRPS)
	if burst < 1 {
		burst = 1
	}
	globalBurst := int(globalRPS * 2)
	if globalBurst < 1 {
		globalBurst = 1
	}
	return &RateLimiter{
		global:     rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		perIP:      cache,
		perIPRate:  rate.Limit(perIPRPS),
		trustProxy: trustProxy,
	}
}

// Middleware wraps next and rejects requests that exceed the rate limits.
// /healthz and /readyz are exempt from rate limiting — they serve
// orchestrators that poll at fixed intervals.
// /metrics is served on a separate listener (METRICS_ADDR) and never reaches this middleware.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Operational endpoints are never rate-limited.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r, rl.trustProxy)

		// Check per-IP limiter first — avoids consuming the global token on IP-level rejections.
		limiter := rl.getOrCreateIPLimiter(ip)
		if !limiter.Allow() {
			slog.Warn("per-IP rate limit exceeded", "ip", ip, "path", r.URL.Path)
			rejectTooManyRequests(w)
			return
		}

		// Check global limiter — only reached if per-IP check passed.
		if !rl.global.Allow() {
			slog.Warn("global rate limit exceeded", "ip", ip, "path", r.URL.Path)
			rejectTooManyRequests(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getOrCreateIPLimiter returns the token bucket for ip, creating one if needed.
func (rl *RateLimiter) getOrCreateIPLimiter(ip string) *rate.Limiter {
	rl.perIPMu.Lock()
	defer rl.perIPMu.Unlock()
	if l, ok := rl.perIP.Get(ip); ok {
		return l
	}
	burst := int(rl.perIPRate)
	if burst < 1 {
		burst = 1
	}
	l := rate.NewLimiter(rl.perIPRate, burst)
	rl.perIP.Add(ip, l)
	return l
}

// clientIP extracts the client IP for rate limiting.
// When trustProxy is true, the rightmost IP in X-Forwarded-For is used
// (appended by the trusted proxy, not attacker-controlled).
// When trustProxy is false (default), r.RemoteAddr is always used.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// The rightmost entry is appended by the trusted proxy — use it.
			parts := strings.Split(xff, ",")
			rightmost := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(rightmost) != nil {
				return rightmost
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rejectTooManyRequests writes a 429 response with Retry-After: 1.
func rejectTooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "RATE_LIMIT_EXCEEDED",
		"detail": "Too many requests. Retry after 1 second.",
	})
}
