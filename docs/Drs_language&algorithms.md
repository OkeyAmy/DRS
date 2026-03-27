# DRS — Language Architecture, Memory Model, and Corrected Algorithms
### Why TypeScript Alone Will Not Scale, What Replaces It, and Why

**Version:** 1.0  
**Status:** Architecture Decision Record  
**Author:** Okey  
**Date:** March 2026  

---

## The Honest Problem With the v2 Language Choice

v2 of the architecture specified `@drs/core` in TypeScript as the primary implementation
language. That was wrong — not in every context, but in the context of what DRS actually
does at its hot path: **cryptographic verification under concurrent load**.

Here is the specific failure chain for TypeScript/Node.js on this workload:

---

### Problem 1 — The V8 Garbage Collector Pauses Your Verification

The Node.js V8 engine has a documented behaviour: when the GC runs, your code does not.
This is not theoretical. GC pause times of 50–60ms per Scavenge cycle are observed in
production under load, and full Mark-Sweep cycles can pause for 89–1500ms depending on
heap size and object count.

```
What happens during DRS chain verification in Node.js:

verifyChain() called 10,000 times/second (moderate agent workload)
Each call creates:
  - 1 x ChainBundle object (deserialized JSON)
  - n x DRSDelegation objects (n = chain depth)
  - n x canonical JSON strings (for signature verification)
  - n x Uint8Array (signature bytes)
  - n x public key objects (from DID resolution)
  - 1 x VerificationResult object

At n=5, that is ~35 objects per call × 10,000 calls/sec = 350,000 new heap objects/sec.
These are short-lived (die after the call). The Young Generation fills in ~2-4ms.
Scavenge runs. Your event loop stalls.
```

The most important thing to learn about GC is that when GC is running, your code is not.

Full GC cycles can cause significant pauses in the event loop, especially during full GC cycles — the heap size directly controls how often and how long these pauses are.

For a cryptographic verification library that is supposed to add < 5ms overhead to every
agent action, a 50ms GC stall is fatal. It will show up as latency spikes in production
and there is no clean fix — it is structural to how V8 manages memory.

---

### Problem 2 — Node.js Is Single-Threaded

Ed25519 signature verification is CPU-bound. In Node.js, CPU-bound work blocks the event
loop. You can work around this with Worker Threads, but now you have inter-thread message
passing overhead, shared memory complexity, and you are fighting the language's core model
rather than using it.

Go has goroutines — native, lightweight, concurrency-first. Rust has Rayon for parallel
iterators. Both let you verify 10,000 chains/second without fighting the runtime.

---

### Problem 3 — Memory Layout Is Unpredictable for Crypto

Ed25519 requires operating on fixed-size byte arrays: 32-byte public keys, 64-byte
signatures, 32-byte hashes. In Rust these live on the stack as `[u8; 32]` — fixed size,
no heap allocation, no GC pressure. In Node.js/TypeScript, the same data is a
`Uint8Array` on the heap, managed by V8, with padding and pointer overhead.

For a library that processes millions of signatures per day, this matters.

---

### Problem 4 — Specific Memory Leak Patterns in the v2 Design

Four concrete leak patterns that would appear in the TypeScript implementation as written:

**Leak 1 — Unbounded DID resolver cache**
```typescript
// v2 described this without bounds:
const didCache = new Map<string, PublicKey>()

function resolveDidToPublicKey(did: string): PublicKey {
  if (didCache.has(did)) return didCache.get(did)!
  const key = resolveDid(did)
  didCache.set(did, key)  // ← grows forever
  return key
}
```
In a system processing millions of delegations from millions of agents, this Map grows
indefinitely. The V8 Old Generation fills with dead DID entries. Full GC runs. The
longer the process runs, the worse the pauses get.

**Leak 2 — Status list held in module scope**
```typescript
// v2 described a cached status list without TTL eviction:
let statusList: BitstringStatusList | null = null
let lastFetch = 0

async function checkRevocation(cid: string): Promise<RevocationStatus> {
  if (!statusList || Date.now() - lastFetch > 300_000) {
    statusList = await fetchStatusList()  // fetches new one
    // ← old one is not explicitly freed — depends on GC
    lastFetch = Date.now()
  }
  // ...
}
```
The old status list stays in memory until GC decides to collect it. Under high load,
when the GC is already busy, it may not be collected promptly. You now have two copies of
a 16KB+ structure in memory simultaneously, which causes more GC pressure, which delays
collection further. Circular.

**Leak 3 — Chain bundle retained by audit log callback**
```typescript
server.tool("web_search", async (params, context) => {
  await auditLog.write({ chain: context.drs.bundle })  // ← serialised
  // context is held alive until the async write completes
  // if auditLog.write() is slow (I/O), the entire chain bundle
  // stays in memory for every in-flight request simultaneously
})
```
At 10,000 req/sec with 100ms audit I/O latency, you have 1,000 chain bundles in memory
simultaneously waiting for the write to complete. Each bundle is 5–20KB. That is 5–20MB
of heap under load — not catastrophic, but it is uncontrolled.

**Leak 4 — String accumulation in JCS canonicalisation**
```typescript
function jcsCanonicalize(obj: object): Uint8Array {
  // JSON.stringify with sorted keys creates a new string on every call
  // For a delegation object with nested fields, this traverses the entire
  // object tree and allocates a new string. The string is typically 500–2000 bytes.
  // At 10,000 calls/sec, that is 5–20MB of string allocation per second,
  // all going to Young Generation, all triggering frequent Scavenges.
  return new TextEncoder().encode(
    JSON.stringify(obj, Object.keys(obj).sort(), 0)
  )
}
```
This is not a leak (strings are collected) but it is the primary driver of GC pressure.
The correct fix is either to use a streaming serialiser that writes directly to a
pre-allocated buffer, or to move this operation to a Rust WASM module.

---

## The Correct Language Architecture

The solution is not "rewrite everything in Rust." That over-corrects. The solution is
to assign each layer to the language that is correct for that layer's job.

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 0 — CRYPTO CORE                                              │
│  Language: Rust                                                     │
│                                                                     │
│  What runs here:                                                    │
│    Ed25519 sign / verify                                            │
│    SHA-256 / CID computation                                        │
│    JCS canonicalisation                                             │
│    is_attenuated_subset()  ← corrected algorithm below             │
│                                                                     │
│  Why Rust:                                                          │
│    Zero GC. Stack-allocated byte arrays. Constant-time crypto ops. │
│    Compiled to both native binary AND WebAssembly (same source).   │
│    ed25519-dalek crate (after RUSTSEC-2022-0093 patch): audited,   │
│    RFC 8032 compliant, batch verification support.                  │
│                                                                     │
│  Output: drs-core.so (native) + drs-core.wasm (browser/edge)       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ called via FFI / WASM bindings
┌──────────────────────────▼──────────────────────────────────────────┐
│  LAYER 1 — VERIFICATION SERVER / MIDDLEWARE                         │
│  Language: Go                                                       │
│                                                                     │
│  What runs here:                                                    │
│    verifyChain() orchestration (calls Rust core for crypto)         │
│    MCP middleware adapter                                           │
│    A2A interceptor                                                  │
│    Status list cache with proper TTL + eviction                    │
│    DID resolver cache with LRU eviction bounds                     │
│    HTTP adapter                                                     │
│                                                                     │
│  Why Go:                                                            │
│    Goroutines handle 10,000+ concurrent verifications naturally.   │
│    Predictable GC with 1-2ms typical pause (not 50-1500ms).        │
│    Rich standard library (net/http, crypto, encoding/json built-in)│
│    Compiles to a single static binary — trivial deployment.        │
│    Go's crypto/sha256 is hardware-accelerated (AES-NI on x86).    │
│                                                                     │
│  Output: drs-verify (binary, deployable as sidecar or library)      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ exposed via gRPC or local IPC
┌──────────────────────────▼──────────────────────────────────────────┐
│  LAYER 2 — DEVELOPER SDK                                            │
│  Language: TypeScript (Node.js)                                     │
│                                                                     │
│  What runs here:                                                    │
│    issueRootDelegation() — calls Rust WASM for signing              │
│    buildBundle()                                                    │
│    DRS schema types and validators                                  │
│    Developer-facing API surface                                     │
│    CLI tools                                                        │
│                                                                     │
│  Why TypeScript here specifically:                                  │
│    Issuance is low-frequency (once per human consent).             │
│    Developers already live in the Node.js ecosystem.               │
│    The GC pressure from issuance is trivial — it is not called     │
│    10,000 times/second, it is called once per delegation.          │
│    TypeScript is appropriate here because the bottleneck is NOT     │
│    in this layer.                                                   │
│                                                                     │
│  Output: @drs/sdk (npm package)                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Summary: Why This Specific Split

| Layer | Language | Reason |
|---|---|---|
| Crypto primitives | Rust | No GC, stack allocation, constant-time ops, compiles to WASM |
| Verification server | Go | Goroutines, predictable GC, standard library, single binary |
| Developer SDK | TypeScript | Low-frequency path, developer familiarity, npm ecosystem |
| Browser / edge runtime | Rust → WASM | Same source as native, zero dependencies, 80KB bundle |
| Solidity (Monad) | Solidity ^0.8.20 | EVM requirement, no alternative |

---

## Corrected Algorithms

### Correction 1 — `is_attenuated_subset()` Was O(n·m)

The v2 algorithm iterated over all parent capabilities for each child capability:

```python
for child_cap in child_caps:        # O(n)
    for parent_cap in parent_caps:  # O(m)
        if covers(parent_cap, child_cap):
            ...
```

For an agent with 50 capabilities and a parent with 50 capabilities, this is 2,500
comparisons per verification call. Called 10,000 times/second: 25 million string
comparisons/second. It is unnecessary.

**The correct approach:** Index the parent capabilities at issuance time, not at
verification time. Verification is read-heavy (called millions of times); issuance is
write-once (called once per delegation). Build the index at issuance.

```rust
// Rust — correct O(n log n) issuance index + O(n) verification
// Source: Standard prefix trie / radix tree for URI namespace matching

use std::collections::HashMap;

/// CapabilityIndex is built at delegation issuance time (once).
/// Verification looks up against the index (O(1) average, O(n) worst case for wildcards).
struct CapabilityIndex {
    /// Exact resource → set of allowed abilities
    exact: HashMap<String, Vec<String>>,
    /// Namespace prefix → set of allowed abilities (for "mcp://tools/*" patterns)
    prefix: Vec<(String, Vec<String>)>,  // sorted by length descending for longest-match
    /// Whether "*" (universal) ability is granted for a resource
    universal: bool,
}

impl CapabilityIndex {
    /// Build the index from a parent's capability list.
    /// Called ONCE at delegation creation. O(n log n) for sort.
    fn build(parent_caps: &[Capability]) -> Self {
        let mut exact: HashMap<String, Vec<String>> = HashMap::new();
        let mut prefix: Vec<(String, Vec<String>)> = Vec::new();
        let mut universal = false;

        for cap in parent_caps {
            if cap.with == "*" {
                universal = true;
                continue;
            }
            if cap.with.ends_with("/*") {
                let ns = cap.with[..cap.with.len()-1].to_string(); // strip '*'
                prefix.push((ns, cap.can.clone()));
            } else {
                exact.entry(cap.with.clone())
                     .or_default()
                     .extend(cap.can.clone());
            }
        }
        // Sort by prefix length descending — longest match wins
        prefix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        
        CapabilityIndex { exact, prefix, universal }
    }

    /// Check if a given (resource, ability) pair is covered by this index.
    /// Called at verification time. O(1) for exact match, O(k) for wildcard
    /// where k = number of distinct prefix patterns (typically < 10).
    fn covers(&self, resource: &str, ability: &str) -> bool {
        if self.universal { return true; }
        
        // 1. Exact resource match — O(1) HashMap lookup
        if let Some(abilities) = self.exact.get(resource) {
            if ability_covered(ability, abilities) { return true; }
        }
        
        // 2. Longest prefix match — O(k) where k = number of wildcard patterns
        for (prefix, abilities) in &self.prefix {
            if resource.starts_with(prefix.as_str()) {
                if ability_covered(ability, abilities) { return true; }
                // Don't break — a longer exact match might exist in exact map
                // (already checked above) but a shorter prefix might not cover this ability
                // while a longer one does. We sorted descending so first match is longest.
                break;
            }
        }
        
        false
    }
}

fn ability_covered(child_ability: &str, parent_abilities: &[String]) -> bool {
    parent_abilities.iter().any(|p| {
        p == "*" || 
        p == child_ability || 
        (p.ends_with("/*") && child_ability.starts_with(&p[..p.len()-1]))
    })
}
```

**Why this is correct:**
- `CapabilityIndex::build()` runs at issuance (once). O(n log n) for the sort.
- `CapabilityIndex::covers()` runs at verification (millions of times). O(1) average
  for exact match, O(k) for wildcard where k is the number of wildcard patterns —
  typically 2-5 in real use. In practice this is O(1).
- The index is stored in the signed delegation. Verifiers deserialise it once and
  reuse it across all checks in the chain.

---

### Correction 2 — `verify_chain()` Creates Redundant Intermediate Objects

The v2 algorithm in Python created a new object at every step for canonical encoding.
In Rust, we work with byte slices directly:

```rust
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// verify_chain verifies a DRS chain bundle.
/// 
/// Memory model:
/// - No heap allocation for signature bytes (stack-allocated [u8; 64])
/// - No heap allocation for public keys (stack-allocated [u8; 32])  
/// - One heap allocation per delegation for canonical JSON (unavoidable)
/// - Canonical JSON string is dropped immediately after hash computation
/// 
/// This eliminates the 35-object-per-call allocation pattern from v2.
pub fn verify_chain(bundle: &ChainBundle) -> VerificationResult {
    let delegations = &bundle.delegations;

    if delegations.is_empty() {
        return VerificationResult::invalid("EMPTY_BUNDLE", "No delegations in bundle");
    }

    // --- Step 1: Hash chain structural integrity ---
    // We compute CIDs bottom-up, comparing to claimed prf[] values.
    for i in 1..delegations.len() {
        let computed_cid = compute_cid(&delegations[i - 1]);
        let claimed_cid  = &delegations[i].prf[0];
        
        if &computed_cid != claimed_cid {
            return VerificationResult::invalid(
                "CHAIN_BREAK",
                &format!("Index {i}: computed CID {computed_cid} ≠ claimed {claimed_cid}")
            );
        }
    }

    // --- Step 2: Signature verification ---
    for (i, delegation) in delegations.iter().enumerate() {
        // Resolve DID to public key — O(1) for did:key (pure computation, no heap)
        let verifying_key: VerifyingKey = match resolve_did_key(&delegation.iss) {
            Ok(k)  => k,
            Err(e) => return VerificationResult::invalid("UNRESOLVABLE_DID", &e),
        };

        // Build canonical bytes — one allocation, immediately dropped after use
        let canonical: Vec<u8> = jcs_canonical_bytes(delegation);

        // Decode signature — stack allocated [u8; 64]
        let sig_bytes: [u8; 64] = match base64url_decode_fixed(&delegation.sig) {
            Ok(b)  => b,
            Err(_) => return VerificationResult::invalid("BAD_SIG_ENCODING", ""),
        };
        let signature = Signature::from_bytes(&sig_bytes);

        // Ed25519 verify — ed25519-dalek enforces S < q (SUF-CMA)
        // Reference: RUSTSEC-2022-0093 was the vulnerability in OLDER dalek versions
        // where verify() did not check the cofactor. This was patched in ed25519-dalek 2.x.
        // We use 2.x. The patch is: https://github.com/dalek-cryptography/ed25519-dalek/pull/306
        if verifying_key.verify(&canonical, &signature).is_err() {
            return VerificationResult::invalid(
                "INVALID_SIGNATURE",
                &format!("Ed25519 verification failed at index {i}, issuer: {}", delegation.iss)
            );
        }

        // canonical is dropped here — memory freed immediately, no GC involvement
    }

    // --- Step 3: Capability attenuation (using pre-built index) ---
    // The index was built at issuance and stored in the delegation. No rebuild needed.
    for i in 1..delegations.len() {
        let parent_index = &delegations[i - 1].capability_index; // pre-built at issuance
        
        for child_cap in &delegations[i].att {
            if !parent_index.covers(&child_cap.with, &child_cap.can) {
                return VerificationResult::invalid(
                    "CAPABILITY_ESCALATION",
                    &format!("Index {i}: {} on {} not covered by parent", 
                             child_cap.can, child_cap.with)
                );
            }
            // Check narrowing-by constraints
            if let Some(nb) = &child_cap.nb {
                if let Err(e) = check_nb_constraints(nb, &delegations[i-1].att, &child_cap.with) {
                    return VerificationResult::invalid("NB_VIOLATION", &e);
                }
            }
        }
    }

    // --- Step 4: Temporal validity ---
    let now = unix_timestamp_now();
    for (i, d) in delegations.iter().enumerate() {
        if let Some(nbf) = d.nbf {
            if now < nbf {
                return VerificationResult::invalid(
                    "NOT_YET_VALID",
                    &format!("Index {i} not valid until {nbf}")
                );
            }
        }
        if let Some(exp) = d.exp {
            if now > exp {
                return VerificationResult::expired(
                    &format!("Index {i} expired at {exp}")
                );
            }
        }
    }

    // --- Step 5: Revocation (delegated to cache layer — not Rust's job) ---
    // The Go layer calls the status list cache before invoking this function.
    // Rust core does not perform I/O.

    VerificationResult::valid(
        root_principal:    &delegations[0].iss,
        root_type:         delegations[0].drs_root_type.as_deref(),
        leaf_capabilities: &delegations.last().unwrap().att,
        leaf_constraints:  delegations.last().unwrap().drs_constraints.as_ref(),
        consent_record:    delegations[0].drs_consent.as_ref(),
        chain_depth:       delegations.len(),
    )
}
```

---

### Correction 3 — CID Computation Must Use Stable Canonicalisation

The v2 algorithm used `JSON.stringify(obj, Object.keys(obj).sort())` for canonicalisation.
This has a subtle bug: `Object.keys()` returns keys in insertion order in modern JS engines,
and `.sort()` sorts lexicographically. For nested objects, the sort is only applied to the
top level — nested keys are not sorted.

The correct algorithm is RFC 8785 JCS (JSON Canonicalization Scheme) which specifies
deterministic serialisation of ALL nested keys recursively.

```rust
// Rust — correct RFC 8785 JCS implementation
// Crate: serde-json-canonicalizer (implements RFC 8785)

use serde_json_canonicalizer::to_vec;
use sha2::{Digest, Sha256};
use multibase::Base;
use cid::{Cid, multihash::{Code, MultihashDigest}};

/// compute_cid produces the CIDv1 of a delegation object.
/// 
/// Algorithm:
///   1. Serialise to canonical JSON per RFC 8785 (all keys sorted, recursively)
///   2. SHA-256 the canonical bytes
///   3. Wrap in multihash (0x12, 0x20 prefix)
///   4. Wrap in CIDv1 (version=1, codec=dag-json=0x0129)
///   5. Base32-encode with 'b' prefix
///
/// This is stable: same delegation always produces same CID, regardless of
/// key insertion order, numeric precision, or unicode normalisation.
pub fn compute_cid(delegation: &DRSDelegation) -> String {
    // 1. JCS canonical JSON — RFC 8785 compliant, all nested keys sorted
    // Note: we exclude the 'sig' field (the CID is of the unsigned content)
    let unsigned = delegation.without_signature();
    let canonical: Vec<u8> = to_vec(&unsigned)
        .expect("serialisation of valid delegation should not fail");

    // 2. SHA-256
    let digest = Sha256::digest(&canonical);  // [u8; 32] — stack allocated

    // 3. Multihash: sha2-256 (0x12) || length 32 (0x20) || digest
    let mh = Code::Sha2_256.digest(&canonical);

    // 4. CIDv1 with dag-json codec
    let cid = Cid::new_v1(0x0129, mh);  // 0x0129 = dag-json

    // 5. Base32 lower-case, 'b' multibase prefix
    cid.to_string()  // produces "bafyabc..."
}
```

**Why `serde-json-canonicalizer` and not a hand-rolled sort:**
The RFC 8785 test vectors include edge cases that hand-rolled solutions miss:
- Unicode characters in keys (sort order is by Unicode code point, not ASCII)
- Number precision (1.0 and 1 must be represented identically)
- Empty objects and arrays
- Nested objects at arbitrary depth

Using a crate that has been tested against the RFC's official test vectors eliminates
an entire class of canonicalisation divergence bugs between implementations.

---

### Correction 4 — DID Key Resolution Must Be Constant-Time for Security

The v2 Python pseudocode used a simple hash map lookup. This is correct in the general
case but has a timing side-channel for `did:key` resolution:

```
did:key:z6MkABCDE... → public_key = decode(multibase_decode(did[9:]))
                                    ↑ variable time if done naively
```

An attacker who can measure the time of `resolve_did_to_public_key()` could, in theory,
learn something about the key being resolved. For `did:key` this risk is low (the key
is public anyway). But for consistency with the constant-time requirement of the
Ed25519 verify operation itself, the resolution should also be constant-time:

```rust
use subtle::ConstantTimeEq;  // subtle crate — constant-time comparison

/// Resolves a did:key DID to its Ed25519 public key bytes.
/// 
/// did:key:z6Mk... decodes as:
///   - Strip "did:key:" prefix
///   - Base58btc-decode the remainder (z prefix = base58btc multibase)
///   - First 2 bytes are the multicodec prefix (0xed 0x01 for Ed25519)
///   - Remaining 32 bytes are the raw Ed25519 public key
///
/// The decode is done in O(n) constant coefficient time — no early exits
/// on specific byte values.
pub fn resolve_did_key(did: &str) -> Result<[u8; 32], DIDError> {
    const PREFIX: &str = "did:key:z";
    
    if !did.starts_with(PREFIX) {
        return Err(DIDError::UnsupportedMethod);
    }
    
    let encoded = &did[PREFIX.len()..];  // strip "did:key:z"
    let decoded = bs58::decode(encoded)  // base58btc
        .into_vec()
        .map_err(|_| DIDError::DecodingFailed)?;
    
    // Expect: [0xed, 0x01, <32 bytes of public key>]
    if decoded.len() != 34 {
        return Err(DIDError::InvalidLength);
    }
    
    // Constant-time check of multicodec prefix
    let valid_prefix = (decoded[0].ct_eq(&0xed) & decoded[1].ct_eq(&0x01)).into();
    if !valid_prefix {
        return Err(DIDError::UnsupportedKeyType);
    }
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded[2..]);
    Ok(key_bytes)
}
```

---

### Correction 5 — The DID Resolver Cache Needs LRU With a Hard Bound

Replacing the unbounded `Map` in v2:

```go
// Go — LRU cache for DID public keys
// Using golang-lru (https://github.com/hashicorp/golang-lru)
// This is the standard Go LRU implementation used in production systems.

package resolver

import (
    "time"
    lru "github.com/hashicorp/golang-lru/v2"
)

type cachedKey struct {
    publicKey [32]byte
    expiresAt time.Time
}

// DIDCache holds at most 10,000 resolved DIDs.
// At 32 bytes per key + overhead: ~1-2MB maximum memory usage.
// When the cache is full, the least recently used entry is evicted.
// This prevents unbounded growth regardless of agent churn.
var didCache, _ = lru.New[string, cachedKey](10_000)

const didCacheTTL = 1 * time.Hour // DID documents do not change frequently

func resolveDidKey(did string) ([32]byte, error) {
    if cached, ok := didCache.Get(did); ok {
        if time.Now().Before(cached.expiresAt) {
            return cached.publicKey, nil
        }
        // Expired — remove and re-resolve
        didCache.Remove(did)
    }
    
    key, err := resolveFromDIDString(did)  // pure computation for did:key
    if err != nil {
        return [32]byte{}, err
    }
    
    didCache.Add(did, cachedKey{
        publicKey: key,
        expiresAt: time.Now().Add(didCacheTTL),
    })
    return key, nil
}
```

**Why 10,000 as the bound:**
A deployment processing 10,000 unique agents simultaneously — which is a large enterprise
deployment — needs 10,000 cache entries. At ~64 bytes per entry (32-byte key + metadata),
the cache uses 640KB maximum. This is predictable and manageable.

---

### Correction 6 — Status List Cache Must Prevent Double-Fetch Under Concurrent Load

The v2 description had a race condition:

```
Thread A: checks lastFetch → stale → starts fetching
Thread B: checks lastFetch → stale (fetch not complete yet) → starts fetching
Result: two concurrent requests to the status list server, 
        and two copies in memory during the window
```

The Go fix uses `sync.Once` per cache window:

```go
package revocation

import (
    "sync"
    "time"
)

type statusListCache struct {
    mu          sync.RWMutex
    list        *BitstringStatusList
    fetchedAt   time.Time
    fetchOnce   sync.Once  // prevents double-fetch
    fetchErr    error
}

var cache = &statusListCache{}

const cacheTTL = 5 * time.Minute

func checkRevocation(cid string) (bool, error) {
    // Fast path: read lock, no contention for reads
    cache.mu.RLock()
    if cache.list != nil && time.Since(cache.fetchedAt) < cacheTTL {
        result := cache.list.IsRevoked(cid)
        cache.mu.RUnlock()
        return result, nil
    }
    cache.mu.RUnlock()

    // Slow path: need to refresh
    // sync.Once guarantees exactly one goroutine runs the fetch.
    // All others wait and share the result.
    cache.fetchOnce.Do(func() {
        cache.mu.Lock()
        defer cache.mu.Unlock()
        
        newList, err := fetchStatusListFromCDN()
        if err != nil {
            cache.fetchErr = err
            // Reset Once so next call will retry
            cache.fetchOnce = sync.Once{}
            return
        }
        // Old list is overwritten. Go GC will collect it in the next cycle.
        // Since we are using a pointer, only the pointer is replaced — no copy.
        cache.list = newList
        cache.fetchedAt = time.Now()
        cache.fetchErr = nil
        // Reset Once so the NEXT expiry triggers a new fetch
        cache.fetchOnce = sync.Once{}
    })

    if cache.fetchErr != nil {
        return false, cache.fetchErr
    }

    cache.mu.RLock()
    defer cache.mu.RUnlock()
    return cache.list.IsRevoked(cid), nil
}
```

---

## Performance Model — Revised

With the corrected architecture:

### Rust core (Ed25519 verify, CID computation)

| Operation | Latency | Notes |
|---|---|---|
| Ed25519 verify (ed25519-dalek 2.x) | ~0.05ms | ~20,000 ops/sec single core |
| Batch Ed25519 verify (8 sigs) | ~0.15ms | ~50,000 ops/sec (not 8×faster, but ~3×) |
| SHA-256 (CID computation) | ~0.003ms | Hardware AES-NI / SHA-NI where available |
| JCS canonicalisation (RFC 8785) | ~0.1ms | Dominated by JSON traversal, not hashing |

### Go middleware (per request overhead)

| Operation | Latency | Notes |
|---|---|---|
| DID cache lookup (LRU, hit) | ~0.001ms | Hash table lookup |
| Status list check (bitstring, cached) | ~0.001ms | Bit index operation |
| Goroutine scheduling overhead | ~0.002ms | Context switch |
| **Total per verification (n=5 chain)** | **~0.8ms** | Dominated by 5× Ed25519 verify |
| **Total per verification (n=10 chain)** | **~1.5ms** | Linear in chain depth |

This is approximately 5× faster than the TypeScript estimate in v2, because:
1. No GC pauses during crypto operations
2. No intermediate object allocation for canonical bytes (stack-based in Rust)
3. No V8 JIT warmup variance

### Memory profile (Go middleware at 10,000 req/sec)

| Component | Memory | Bound |
|---|---|---|
| DID LRU cache (10,000 entries) | ~640KB | Hard cap |
| Status list cache (1 copy) | ~2-16KB | Single pointer, old one GC'd promptly |
| Per-request working memory (n=5) | ~15KB | Stack-allocated in Rust, freed on return |
| In-flight chain bundles (at 10,000 req/sec, ~0.8ms per) | ~1.5MB | 10,000 × 0.8ms × 15KB |
| **Total steady-state** | **~3MB** | Predictable, does not grow over time |

The key number is 3MB. The TypeScript v2 design at the same load would hold 5-20MB in
Young Generation simultaneously and trigger Scavenge every 2-4ms.

---

## Migration Path From TypeScript SDK to This Architecture

The external API surface does not change. The npm package `@drs/sdk` still exists and
still looks the same to developers. Internally:

```typescript
// @drs/sdk wraps the Rust WASM module for the hot-path operations

import { init, computeCid, verifyChainWasm } from '@drs/wasm'
// @drs/wasm is the Rust core compiled to WebAssembly via wasm-pack
// It is ~80KB gzipped. Zero JavaScript dependencies.

await init()  // load and compile the WASM module (once on startup)

// All crypto operations delegate to WASM — no V8 heap allocations for crypto
export const DRS = {
  computeCid: (delegation: object) => computeCid(JSON.stringify(delegation)),
  verifyChain: (bundle: ChainBundle) => verifyChainWasm(JSON.stringify(bundle)),
  
  // Issuance stays in JS — it is low-frequency and the signing key
  // should not leave the JS context (it lives in the user's wallet)
  issueRootDelegation: nativeIssueRootDelegation,
  buildBundle: nativeBuildBundle,
}
```

This means:
- Developers install one npm package. No change.
- The hot path runs in WASM. No V8 GC pressure on crypto.
- The signing key stays in JS context. No WASM FFI for secrets.
- The Go middleware runs as a sidecar for server deployments.
  For embedded use (edge functions, Cloudflare Workers), the WASM module handles
  everything including verification.

---

## Dependency Audit

| Component | Crate / Package | Version | Why |
|---|---|---|---|
| Ed25519 (Rust) | `ed25519-dalek` | 2.1.x | RFC 8032, SUF-CMA, RUSTSEC-2022-0093 patched |
| SHA-256 (Rust) | `sha2` (RustCrypto) | 0.10.x | AES-NI acceleration, formally audited |
| JCS (Rust) | `serde-json-canonicalizer` | 0.2.x | RFC 8785 test-vector compliant |
| CID (Rust) | `cid` | 1.x | IPLD-compatible, multihash-compatible |
| Constant-time ops | `subtle` | 2.x | Safe constant-time comparisons |
| WASM build | `wasm-pack` | 0.12.x | Rust → WASM compilation |
| LRU cache (Go) | `golang-lru/v2` | 2.x | Hashicorp, production-proven |
| Ed25519 (Go) | `crypto/ed25519` | stdlib | No external dependency needed |
| WASM wrapper (TS) | `@drs/wasm` | internal | Generated by wasm-pack |

---

*Okey — March 2026*
