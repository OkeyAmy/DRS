# DRS Storage Tiers — Canonical Reference

**Date:** 2026-04-13
**Status:** Authoritative
**Applies to:** DRS v4.0

This document is the single canonical reference for DRS storage tier definitions.
All other documents, SDK types, and verifier configuration must align with this table.

---

## Tier Definitions

| Tier | Name | Trigger | Backend | Retention | Implementation Status |
|------|------|---------|---------|-----------|----------------------|
| 0 | Session | Development / testing | In-process memory (LRU) | Session lifetime only | Implemented (`drs-verify/pkg/store/memory.go`) |
| 1 | Ephemeral | Default production (`STORE_DIR` set) | Local filesystem | 48 hours | Implemented (`drs-verify/pkg/store/filesystem.go`) |
| 2 | Durable | `retention_days > 0` in `drs_regulatory` | S3-compatible object store | As configured | Roadmap |
| 3 | Compliant | `sox` or `hipaa` in `drs_regulatory.frameworks` | WORM-policy object store + RFC 3161 timestamp anchor | 7 years minimum | Implemented (`drs-verify/pkg/anchor/tier3store.go`) |
| 4 | Timestamped | EU AI Act high-risk, or any deployment requiring third-party time proof | Tier 3 backend + RFC 3161 TSToken stored alongside each DR | Framework-mandated minimum | Implemented (`drs-verify/pkg/anchor/rfc3161.go`) |
| 5 | On-Chain | Explicit customer requirement only (blockchain-native enterprise, contractual obligation) | Tier 3 backend + Ethereum mainnet hash anchor | Permanent on-chain proof | Roadmap |

---

## Design Principles

Each tier inherits the guarantees of all lower tiers. Tier 3 includes everything Tier 1 provides, plus WORM and RFC 3161 anchoring.

Tier 5 (on-chain) is never the default. It requires an explicit customer request and the understanding that Ethereum gas costs apply. No DRS deployment below Tier 5 requires a wallet, a token, or any cryptocurrency interaction.

---

## Configuration

Storage tier is selected at deployment time via environment variables. See the root `README.md` for the full configuration reference.

| Tier | Required env vars |
|------|-------------------|
| 0 | None (default when `STORE_DIR` is unset) |
| 1 | `STORE_DIR` |
| 2 | `STORE_DIR` + S3 configuration (roadmap) |
| 3 | `STORE_DIR` + `TSA_URL` |
| 4 | `STORE_DIR` + `TSA_URL` (same as Tier 3; Tier 4 is a Tier 3 deployment with `IncludeTimestamps` enabled) |
| 5 | `STORE_DIR` + `TSA_URL` + Ethereum node configuration (roadmap) |

---

## SDK Type Alignment

The `OperatorConfig.storage_tier` field in `drs-sdk/src/sdk/operator.ts` accepts values `0 | 1 | 2 | 3 | 4 | 5`.

The `store.go` package comment in `drs-verify/pkg/store/store.go` documents all six tiers with implementation status.

---

## As Implemented Today

The tier table above describes the target architecture. Here is what the current
codebase actually implements:

| Tier | Status | Notes |
|------|--------|-------|
| 0 | Working | `drs-verify/pkg/store/memory.go` |
| 1 | Working | `drs-verify/pkg/store/filesystem.go` — local filesystem only; Redis is not implemented. |
| 2 | Not implemented | S3-compatible store is on the roadmap. |
| 3 | Partial | `drs-verify/pkg/anchor/tier3store.go` wraps the filesystem store with RFC 3161 timestamping. WORM enforcement is not present in code — the filesystem does not enforce write-once semantics. TSA failures are logged and the receipt is stored without a timestamp (best-effort). |
| 4 | Partial | Same code path as Tier 3; the distinction is operator-level configuration (`IncludeTimestamps`). Tier 4 is a deployment posture, not a separate backend. |
| 5 | Not implemented | Ethereum anchoring is on the roadmap. |

Timestamp verification in `verify.Chain()` does not fail the chain — timestamp
errors are reported per receipt but do not invalidate the overall result. This
is a deliberate design choice (timestamps are evidence, not a gate) but differs
from what some readers may infer from "cryptographic timestamps" in the tier
description.

---

## Changelog

- **2026-04-13:** Added "As Implemented Today" section with accuracy notes for each tier.
- **2026-04-13:** Created as canonical reference. Aligned SDK, verifier, README, and docs to the six-tier model from `docs/technical_v2.md`.
