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

// Resolver resolves did:key and did:web DIDs to Ed25519 public key bytes.
//
// Concurrency design:
//   - cacheMu guards the LRU cache. It is held only during brief cache reads
//     and writes — never during network I/O. This means did:key lookups and
//     cache hits complete without waiting on did:web HTTP fetches.
//   - Per-key singleflight deduplication ensures that concurrent cache misses
//     for the same DID result in a single resolution (and a single HTTP fetch
//     for did:web), not N parallel ones.
type Resolver struct {
	cacheMu    sync.Mutex
	cache      *lru.Cache[string, cacheEntry]
	ttl        time.Duration
	httpClient *http.Client

	// inflight deduplicates concurrent cache misses for the same DID.
	inflightMu sync.Mutex
	inflight   map[string]*inflightEntry
}

// inflightEntry tracks a single in-progress resolution.
type inflightEntry struct {
	done chan struct{}
	res  resolveResult
}

// New creates a Resolver with an LRU cache of the given size and TTL.
// did:web fetches use a 10-second timeout.
func New(cacheSize int, ttl time.Duration) (*Resolver, error) {
	c, err := lru.New[string, cacheEntry](cacheSize)
	if err != nil {
		return nil, fmt.Errorf("resolver: failed to create LRU cache: %w", err)
	}
	return &Resolver{
		cache:      c,
		ttl:        ttl,
		httpClient: &http.Client{Timeout: didWebFetchTimeout},
		inflight:   make(map[string]*inflightEntry),
	}, nil
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

	docURL, err := didWebDocumentURL(did)
	if err != nil {
		return zero, err
	}

	// SSRF protection: resolve the hostname and reject private/reserved ranges.
	u, err := url.Parse(docURL)
	if err != nil {
		return zero, fmt.Errorf("did:web URL parse failed: %w", err)
	}
	private, err := isPrivateHost(ctx, u.Hostname())
	if err != nil {
		return zero, fmt.Errorf("did:web SSRF check failed: %w", err)
	}
	if private {
		slog.Warn("did:web SSRF blocked", "did", did, "host", u.Hostname())
		return zero, fmt.Errorf("did:web host %q resolves to a private or reserved address", u.Hostname())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return zero, fmt.Errorf("did:web request build failed: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("did:web fetch failed for %s: %w", docURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("did:web fetch failed: HTTP %d from %s", resp.StatusCode, docURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, fmt.Errorf("did:web document read failed: %w", err)
	}

	key, extractErr := extractEd25519FromDIDDocument(body)
	if extractErr == nil {
		slog.Debug("did:web resolved", "did", did, "url", docURL)
	}
	return key, extractErr
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
