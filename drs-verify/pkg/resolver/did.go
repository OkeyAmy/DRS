// Package resolver implements did:key and did:web resolution with an LRU cache.
//
// Security properties:
// - Constant-time multicodec prefix check (crypto/subtle.ConstantTimeCompare, not bytes.Equal)
// - LRU cache hard-capped at configurable size (~640 KB at 10 000 entries)
// - Cache entries expire after configurable TTL (default 1 hr)
// - Only the Ed25519 multicodec prefix (0xed 0x01) is accepted
// - did:web fetches are HTTPS-only; a configurable timeout prevents hanging
package resolver

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	didKeyPrefix          = "did:key:z"
	didWebPrefix          = "did:web:"
	multicodecEd25519Hi   = byte(0xed)
	multicodecEd25519Lo   = byte(0x01)
	ed25519PublicKeyBytes = 32
	multicodecPrefixLen   = 2
	decodedLen            = multicodecPrefixLen + ed25519PublicKeyBytes
	didWebFetchTimeout    = 10 * time.Second
	// maxDIDDocumentBytes caps the DID document body size. A well-formed
	// did:web document is well under 10 KiB; 1 MiB is a generous upper bound
	// that still prevents memory-pressure DoS from attacker-controlled hosts.
	maxDIDDocumentBytes = 1 << 20 // 1 MiB
	// circuitStateCacheSize bounds memory usage of the did:web circuit-breaker
	// state. Each entry is ~200 bytes; 10 000 entries ≈ 2 MB. If an attacker
	// floods the resolver with unique did:web identifiers, LRU eviction discards
	// the oldest entries — acceptable because the rate limiter is the primary
	// defense and evicted entries simply reset to closed on next contact.
	circuitStateCacheSize = 10_000
)

// cacheEntry holds a resolved public key and its expiry time.
type cacheEntry struct {
	key    [ed25519PublicKeyBytes]byte
	expiry time.Time
}

// resolveResult is the return value carried by singleflight.
type resolveResult struct {
	key [ed25519PublicKeyBytes]byte
	err error
}

// circuitState tracks per-DID failure history for the circuit breaker.
type circuitState struct {
	mu        sync.Mutex
	failures  int       // consecutive failure count
	openUntil time.Time // non-zero when circuit is open
}

// isOpen returns true if the circuit is open and the cooldown has not elapsed.
// When the cooldown has elapsed, resets to closed and allows one probe.
func (s *circuitState) isOpen(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.openUntil.IsZero() {
		return false
	}
	if now.After(s.openUntil) {
		// Cooldown elapsed — allow one probe through, reset circuit.
		s.openUntil = time.Time{}
		return false
	}
	return true
}

// recordSuccess resets the circuit.
func (s *circuitState) recordSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
	s.openUntil = time.Time{}
}

// recordFailure increments failure count and opens circuit if threshold is reached.
func (s *circuitState) recordFailure(threshold int, cooldown time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
	if s.failures >= threshold {
		s.openUntil = time.Now().Add(cooldown)
		slog.Warn("did:web circuit opened", "consecutive_failures", s.failures)
	}
}

// Resolver resolves did:key and did:web DIDs to Ed25519 public key bytes.
//
// Concurrency design:
//   - cacheMu guards the LRU cache. It is held only during brief cache reads
//     and writes — never during network I/O. This means did:key lookups and
//     cache hits complete without waiting on did:web HTTP fetches.
//   - Per-key singleflight deduplication ensures that concurrent cache misses
//     for the same DID result in a single resolution (and a single HTTP fetch
//     for did:web), not N parallel ones.
//   - circuitMu guards the circuitStates map. Each circuitState has its own
//     mutex so contention on one DID does not block others.
type Resolver struct {
	cacheMu    sync.Mutex
	cache      *lru.Cache[string, cacheEntry]
	ttl        time.Duration
	httpClient *http.Client

	// inflight deduplicates concurrent cache misses for the same DID.
	inflightMu sync.Mutex
	inflight   map[string]*inflightEntry

	// Circuit breaker state — one entry per did:web DID, capped by LRU.
	// circuitMu guards the get-or-create compound operation on circuitStates.
	// (The underlying LRU is itself thread-safe, but Get-then-Add is not atomic.)
	circuitMu     sync.Mutex
	circuitStates *lru.Cache[string, *circuitState]
	cbThreshold   int
	cbCooldown    time.Duration

	// allowPrivateHosts disables SSRF protection. Only set in tests.
	allowPrivateHosts bool
}

// inflightEntry tracks a single in-progress resolution.
type inflightEntry struct {
	done chan struct{}
	res  resolveResult
}

// New creates a Resolver with an LRU cache of the given size and TTL.
// did:web fetches use a 10-second timeout, a custom DialContext that rejects
// private IPs at connect time (closing DNS-rebinding and redirect-to-private
// SSRF paths), and a redirect policy that forbids redirects entirely.
func New(cacheSize int, ttl time.Duration) (*Resolver, error) {
	c, err := lru.New[string, cacheEntry](cacheSize)
	if err != nil {
		return nil, fmt.Errorf("resolver: failed to create LRU cache: %w", err)
	}
	cs, err := lru.New[string, *circuitState](circuitStateCacheSize)
	if err != nil {
		return nil, fmt.Errorf("resolver: failed to create circuit state cache: %w", err)
	}
	r := &Resolver{
		cache:         c,
		ttl:           ttl,
		inflight:      make(map[string]*inflightEntry),
		circuitStates: cs,
		cbThreshold:   5,
		cbCooldown:    60 * time.Second,
	}
	r.httpClient = &http.Client{
		Timeout: didWebFetchTimeout,
		Transport: &http.Transport{
			DialContext:           r.safeDialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          10,
		},
		// Forbid redirects: did:web documents are served directly; any redirect
		// is either misconfiguration or an attempt to bypass the pre-request
		// hostname check (including redirecting to 169.254.169.254 or similar).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("did:web: redirects not allowed (to %s)", req.URL.Host)
		},
	}
	return r, nil
}

// safeDialContext is the http.Transport.DialContext for r.httpClient.
// It validates every connect attempt (including redirect targets, if they
// were allowed) against the private-IP blocklist, closing DNS-rebinding and
// redirect-to-internal SSRF bypasses that pre-request hostname checks miss.
// Tests set allowPrivateHosts so httptest servers on 127.0.0.1 are reachable.
func (r *Resolver) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safeDial: split host/port %q: %w", addr, err)
	}
	d := net.Dialer{Timeout: 5 * time.Second}

	// If addr is already a literal IP, check and dial directly.
	if ip := net.ParseIP(host); ip != nil {
		if !r.allowPrivateHosts && isPrivateIP(ip) {
			return nil, fmt.Errorf("safeDial: refused connection to private address %s", ip)
		}
		return d.DialContext(ctx, network, addr)
	}

	// Resolve host ourselves so the IP we validate is the IP we connect to.
	// This closes the DNS-rebinding window between pre-check and default-dialer
	// re-resolution.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safeDial: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("safeDial: no addresses for %q", host)
	}
	for _, ia := range ips {
		if !r.allowPrivateHosts && isPrivateIP(ia.IP) {
			return nil, fmt.Errorf("safeDial: %q resolves to private address %s", host, ia.IP)
		}
	}
	// Dial the first resolved IP directly. Using the literal IP (not the
	// hostname) prevents the dialer from re-resolving and reaching a different
	// address than the one we validated.
	target := net.JoinHostPort(ips[0].IP.String(), port)
	return d.DialContext(ctx, network, target)
}

// NewWithCircuitBreaker creates a Resolver with circuit breaker protection for
// did:web endpoints. threshold is the number of consecutive failures before
// the circuit opens. cooldown is how long to wait before attempting a probe.
func NewWithCircuitBreaker(cacheSize int, ttl time.Duration, threshold int, cooldown time.Duration) (*Resolver, error) {
	r, err := New(cacheSize, ttl)
	if err != nil {
		return nil, err
	}
	r.cbThreshold = threshold
	r.cbCooldown = cooldown
	return r, nil
}

// getCircuitState returns the circuitState for the given DID, creating it if absent.
// Entries are stored in a capped LRU to bound memory under attacker-controlled
// DID floods. Eviction of a state only costs the loss of its failure-count
// history — the circuit simply starts closed on next contact.
func (r *Resolver) getCircuitState(did string) *circuitState {
	r.circuitMu.Lock()
	defer r.circuitMu.Unlock()
	if cs, ok := r.circuitStates.Get(did); ok {
		return cs
	}
	cs := &circuitState{}
	r.circuitStates.Add(did, cs)
	return cs
}

// circuitStateCount returns the number of circuit states currently stored.
// Exposed for tests that verify the LRU bound is effective.
func (r *Resolver) circuitStateCount() int {
	r.circuitMu.Lock()
	defer r.circuitMu.Unlock()
	return r.circuitStates.Len()
}

// privateRanges is the set of IP ranges that must not be reachable via did:web.
// Parsed once at init time; panic on invalid CIDR is intentional (programmer error).
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // link-local (AWS IMDS, Azure IMDS)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC 1918 private
		"172.16.0.0/12",  // RFC 1918 private
		"192.168.0.0/16", // RFC 1918 private
		"fc00::/7",       // IPv6 unique local
		"100.64.0.0/10",  // RFC 6598 shared address space (carrier-grade NAT)
		"0.0.0.0/8",      // "this" network
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("resolver: invalid private CIDR %q: %v", cidr, err))
		}
		out = append(out, block)
	}
	return out
}()

// isPrivateIP returns true if ip falls within any of the blocked private ranges.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateHost resolves host to IP addresses and returns true if any resolve
// to a private or reserved range. Defends against SSRF via did:web.
// The DNS lookup uses ctx so it respects request cancellation.
func isPrivateHost(ctx context.Context, host string) (bool, error) {
	// Strip port if present — net.LookupHost does not accept host:port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false, fmt.Errorf("did:web host resolution failed for %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return true, nil
		}
	}
	return false, nil
}

// Resolve resolves a DID to its raw Ed25519 public key bytes.
//
// Supported methods:
//   - did:key — decoded directly from the DID string; no network call
//   - did:web — DID document fetched from https://{domain}/.well-known/did.json
//     (or https://{domain}/{path}/did.json); cached with TTL
//
// Cache hits are served under a brief lock (constant-time).
// Cache misses are resolved outside the lock and deduplicated per-DID
// via singleflight to prevent N parallel fetches for the same DID.
func (r *Resolver) Resolve(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	// Fast path: brief lock for cache lookup only
	r.cacheMu.Lock()
	if entry, ok := r.cache.Get(did); ok {
		if time.Now().Before(entry.expiry) {
			r.cacheMu.Unlock()
			return entry.key, nil
		}
		r.cache.Remove(did)
	}
	r.cacheMu.Unlock()

	// Slow path: singleflight deduplication for cache miss.
	// The inflightMu is held only to check/insert the inflight map entry,
	// never during actual resolution or network I/O.
	r.inflightMu.Lock()
	if e, ok := r.inflight[did]; ok {
		r.inflightMu.Unlock()
		select {
		case <-ctx.Done():
			return [ed25519PublicKeyBytes]byte{}, ctx.Err()
		case <-e.done:
			return e.res.key, e.res.err
		}
	}
	e := &inflightEntry{done: make(chan struct{})}
	r.inflight[did] = e
	r.inflightMu.Unlock()

	key, err := r.resolveUncached(ctx, did)
	e.res = resolveResult{key: key, err: err}
	close(e.done)

	r.inflightMu.Lock()
	delete(r.inflight, did)
	r.inflightMu.Unlock()

	if err == nil {
		r.cacheMu.Lock()
		r.cache.Add(did, cacheEntry{key: key, expiry: time.Now().Add(r.ttl)})
		r.cacheMu.Unlock()
	}

	return key, err
}

// resolveUncached performs the actual resolution without holding any lock.
func (r *Resolver) resolveUncached(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	switch {
	case strings.HasPrefix(did, didKeyPrefix):
		return resolveDidKey(did)
	case strings.HasPrefix(did, didWebPrefix):
		return r.resolveDidWeb(ctx, did)
	default:
		method := "unknown"
		if parts := strings.SplitN(did, ":", 3); len(parts) >= 2 {
			method = parts[1]
		}
		return [ed25519PublicKeyBytes]byte{}, fmt.Errorf("unsupported DID method: %q", method)
	}
}

// resolveDidKey decodes a did:key DID to its raw 32-byte Ed25519 public key.
func resolveDidKey(did string) ([ed25519PublicKeyBytes]byte, error) {
	var zero [ed25519PublicKeyBytes]byte

	if !strings.HasPrefix(did, didKeyPrefix) {
		method := "unknown"
		if parts := strings.SplitN(did, ":", 3); len(parts) >= 2 {
			method = parts[1]
		}
		return zero, fmt.Errorf("unsupported DID method: %q", method)
	}

	encoded := did[len(didKeyPrefix):]

	// did:key uses base58btc encoding (the 'z' multibase prefix is already stripped)
	decoded, err := base58Decode(encoded)
	if err != nil {
		return zero, fmt.Errorf("did:key base58 decoding failed: %w", err)
	}

	if len(decoded) != decodedLen {
		return zero, fmt.Errorf("did:key decoded length %d, expected %d", len(decoded), decodedLen)
	}

	// Constant-time multicodec prefix check using crypto/subtle — not bytes.Equal,
	// which short-circuits on the first differing byte and leaks timing information.
	if subtle.ConstantTimeCompare(decoded[:2], []byte{multicodecEd25519Hi, multicodecEd25519Lo}) != 1 {
		return zero, fmt.Errorf("did:key unsupported key type: multicodec prefix [%#x %#x]", decoded[0], decoded[1])
	}

	var key [ed25519PublicKeyBytes]byte
	copy(key[:], decoded[2:])
	return key, nil
}

// resolveDidWeb fetches the DID document for a did:web DID and extracts its
// Ed25519 public key.
//
// Spec: https://w3c-ccg.github.io/did-method-web/
// DID document URL rules:
//   - did:web:example.com              → https://example.com/.well-known/did.json
//   - did:web:example.com:users:alice  → https://example.com/users/alice/did.json
//   - did:web:example.com%3A8443       → https://example.com:8443/.well-known/did.json
func (r *Resolver) resolveDidWeb(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	var zero [ed25519PublicKeyBytes]byte

	// Parse the DID first so malformed identifiers do not allocate circuit
	// state. A flood of unique garbage DIDs otherwise creates one LRU entry
	// per request (still bounded, but wasted work). Real parsing errors are
	// client mistakes, not endpoint failures — no circuit state belongs to them.
	docURL, err := didWebDocumentURL(did)
	if err != nil {
		return zero, err
	}

	// Circuit breaker: fail fast for recently-broken did:web endpoints.
	cs := r.getCircuitState(did)
	if cs.isOpen(time.Now()) {
		return zero, fmt.Errorf("did:web circuit open for %q — endpoint was recently unreachable", did)
	}

	// SSRF protection: resolve the hostname and reject private/reserved ranges.
	// Bypassed only in tests via allowPrivateHosts.
	if !r.allowPrivateHosts {
		u, err := url.Parse(docURL)
		if err != nil {
			cs.recordFailure(r.cbThreshold, r.cbCooldown)
			return zero, fmt.Errorf("did:web URL parse failed: %w", err)
		}
		private, err := isPrivateHost(ctx, u.Hostname())
		if err != nil {
			cs.recordFailure(r.cbThreshold, r.cbCooldown)
			return zero, fmt.Errorf("did:web SSRF check failed: %w", err)
		}
		if private {
			slog.Warn("did:web SSRF blocked", "did", did, "host", u.Hostname())
			return zero, fmt.Errorf("did:web host %q resolves to a private or reserved address", u.Hostname())
		}
	}

	// Build the fetch URL for tests: allow http:// when the URL already starts with http://
	// (httptest servers use http, not https). In production, didWebDocumentURL always
	// returns https://, so this branch is never reached outside tests.
	fetchURL := docURL
	if r.allowPrivateHosts && strings.HasPrefix(docURL, "https://") {
		// Rewrite https → http so httptest servers (plain HTTP) are reachable.
		fetchURL = "http://" + docURL[len("https://"):]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, fmt.Errorf("did:web request build failed: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, fmt.Errorf("did:web fetch failed for %s: %w", fetchURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, fmt.Errorf("did:web fetch failed: HTTP %d from %s", resp.StatusCode, fetchURL)
	}

	// Cap body size. An attacker-controlled public host could otherwise serve
	// an arbitrarily large "DID document" and drive memory pressure.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDIDDocumentBytes+1))
	if err != nil {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, fmt.Errorf("did:web document read failed: %w", err)
	}
	if len(body) > maxDIDDocumentBytes {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, fmt.Errorf("did:web document exceeds %d byte limit", maxDIDDocumentBytes)
	}

	key, extractErr := extractEd25519FromDIDDocument(body)
	if extractErr != nil {
		cs.recordFailure(r.cbThreshold, r.cbCooldown)
		return zero, extractErr
	}

	cs.recordSuccess()
	slog.Debug("did:web resolved", "did", did, "url", fetchURL)
	return key, nil
}

// didWebDocumentURL converts a did:web DID to its DID document HTTPS URL.
func didWebDocumentURL(did string) (string, error) {
	rest := did[len(didWebPrefix):]

	// First colon separates domain from path; subsequent colons are path separators.
	colonIdx := strings.Index(rest, ":")
	var domain, pathPart string
	if colonIdx < 0 {
		domain = rest
		pathPart = ""
	} else {
		domain = rest[:colonIdx]
		pathPart = rest[colonIdx+1:]
	}

	// Decode percent-encoding in the domain (e.g. "example.com%3A443" → "example.com:443")
	domain, err := url.PathUnescape(domain)
	if err != nil {
		return "", fmt.Errorf("did:web invalid domain encoding: %w", err)
	}

	if domain == "" {
		return "", fmt.Errorf("did:web missing domain in %q", did)
	}

	if pathPart == "" {
		return fmt.Sprintf("https://%s/.well-known/did.json", domain), nil
	}
	// Colons in the path portion become URL path separators
	path := strings.ReplaceAll(pathPart, ":", "/")
	return fmt.Sprintf("https://%s/%s/did.json", domain, path), nil
}

// didDocument is a minimal representation of a W3C DID document sufficient
// for extracting an Ed25519 verification key.
type didDocument struct {
	VerificationMethod []verificationMethod `json:"verificationMethod"`
}

type verificationMethod struct {
	Type               string  `json:"type"`
	PublicKeyMultibase string  `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       *jwkKey `json:"publicKeyJwk,omitempty"`
}

// jwkKey holds the fields needed to extract an Ed25519 key from a JWK.
type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"` // base64url-encoded raw public key bytes
}

// extractEd25519FromDIDDocument parses a DID document and returns the first
// Ed25519 public key found.
//
// Supported verification method types:
//   - Ed25519VerificationKey2020 with publicKeyMultibase ("z" = base58btc)
//   - JsonWebKey2020 with publicKeyJwk (kty=OKP, crv=Ed25519)
func extractEd25519FromDIDDocument(docBytes []byte) ([ed25519PublicKeyBytes]byte, error) {
	var zero [ed25519PublicKeyBytes]byte
	var doc didDocument
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return zero, fmt.Errorf("did:web document JSON parse failed: %w", err)
	}

	for _, vm := range doc.VerificationMethod {
		// Ed25519VerificationKey2020 — publicKeyMultibase with 'z' (base58btc) prefix
		if vm.PublicKeyMultibase != "" && strings.HasPrefix(vm.PublicKeyMultibase, "z") {
			decoded, err := base58Decode(vm.PublicKeyMultibase[1:]) // strip 'z' multibase prefix
			if err != nil {
				continue
			}
			if len(decoded) != decodedLen {
				continue
			}
			// Constant-time multicodec check — same security requirement as did:key
			if subtle.ConstantTimeCompare(decoded[:2], []byte{multicodecEd25519Hi, multicodecEd25519Lo}) != 1 {
				continue
			}
			var key [ed25519PublicKeyBytes]byte
			copy(key[:], decoded[2:])
			return key, nil
		}

		// JsonWebKey2020 — OKP key with Ed25519 curve
		if vm.PublicKeyJwk != nil &&
			vm.PublicKeyJwk.Kty == "OKP" &&
			vm.PublicKeyJwk.Crv == "Ed25519" &&
			vm.PublicKeyJwk.X != "" {
			keyBytes, err := base64.RawURLEncoding.DecodeString(vm.PublicKeyJwk.X)
			if err != nil || len(keyBytes) != ed25519PublicKeyBytes {
				continue
			}
			var key [ed25519PublicKeyBytes]byte
			copy(key[:], keyBytes)
			return key, nil
		}
	}

	return zero, fmt.Errorf("no Ed25519 verification method found in did:web document")
}

// base58Decode decodes a base58btc string.
// Uses the Bitcoin alphabet (123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz).
func base58Decode(s string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Build reverse lookup table
	var lookup [256]int
	for i := range lookup {
		lookup[i] = -1
	}
	for i, c := range alphabet {
		lookup[c] = i
	}

	// Decode big-endian base58 integer
	result := make([]byte, 0, len(s))
	for _, c := range s {
		carry := lookup[c]
		if carry < 0 {
			return nil, fmt.Errorf("invalid base58 character: %q", c)
		}
		for j := len(result) - 1; j >= 0; j-- {
			carry += 58 * int(result[j])
			result[j] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			result = append([]byte{byte(carry % 256)}, result...)
			carry /= 256
		}
	}

	// Add leading zeros for leading '1' characters
	for _, c := range s {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}

	return result, nil
}
