# Contributing to DRS

## Before You Start

Read the architecture documents in `docs/` before touching the crypto or verification layer. The v1 and v2 documents explain what was tried and why it was scrapped. Reading them will save you from proposing something that has already been invalidated.

The verification algorithm is documented in `docs/Drs_language&algorithms.md`. If you are changing anything in `drs-verify/pkg/verify/` or `drs-core/src/`, start there.

---

## What Needs Work

The issue tracker has scoped work across four areas:

**Security hardening** — the audit findings are documented with exact file paths, line numbers, and clear acceptance criteria. These require solid Go or Rust knowledge. They are not beginner tasks.

**Protocol implementation** — structured logging, circuit breaker for `did:web` resolution, rate limiting, nonce protection on the `/verify` endpoint. Each issue has a defined interface and a clear definition of done.

**SDK and tooling** — encrypted key storage in the TypeScript CLI, `key list` / `key export` commands, correlation ID support across receipt types. These touch Go types, Rust structs, and TypeScript simultaneously.

**Examples** — DRS wired into real agentic systems. Pick a system you already use. Wire DRS into it. Show what it looks like in production.

---

## Standards

**Every non-trivial function must have a test.** Tests are not written after the fact. Happy path, boundary conditions, error paths, and security properties — all of them.

**Error handling is not optional.** In a cryptographic verification library, a silent failure is a security vulnerability. Return errors explicitly. Never swallow them.

- Rust: use `Result<T, E>` — no `unwrap()` in library code
- Go: always check and propagate errors — no `_` on error returns in production paths
- TypeScript: type your errors — no `catch (e: any)`

**Formatting is enforced by CI.** `rustfmt` for Rust, `gofmt` for Go, `prettier` for TypeScript. If CI rejects your formatting, fix it.

**Capability checks are fail-closed.** If a check errors, the capability is denied. Never default to permit on error.

---

## Pull Requests

- CI must be green before requesting review
- One responsibility per PR — a fix and a refactor are two PRs
- If you are changing the verification algorithm, include test vectors
- If you are adding a new endpoint or middleware, include integration tests

---

## Examples

The one rule: use a real system, not a toy project built for this. A LangChain agent, an AutoGen workflow, a custom MCP server, a CLI tool that calls external APIs — anything that delegates actions on behalf of a human qualifies.

Put your example in `examples/<short-name>/` with a `README.md` that explains what the agent does, where DRS verification happens in the code, and how to run it.

---

## Questions

Open an issue. If you are stuck on the SDK or verifier behavior, describe what you expected, what you got, and what you tried. Minimal reproducible examples are appreciated.
