# Testing Standards

Every source file has a corresponding test file. Tests are not optional and are not written after the fact.

## File structure

```
# Rust
drs-core/src/chain/verify.rs
drs-core/src/chain/verify_test.rs   ← or #[cfg(test)] module inline

# Go
drs-verify/pkg/verify/chain.go
drs-verify/pkg/verify/chain_test.go ← same package, _test.go suffix

# TypeScript
drs-sdk/src/sdk/issue.ts
drs-sdk/src/sdk/issue.test.ts
```

## What must be tested

For every module, write tests covering:

**Happy path:** Expected input produces expected output.

**Boundary conditions:**
- Empty input (empty chain, empty policy, empty args)
- Maximum chain depth (10 hops)
- Expired timestamps (`now > exp`)
- Not-yet-valid timestamps (`now < nbf`)

**Error paths:** Every `Err(...)`, `error` return, and `DrsError` throw has at least one test that triggers it.

**Security properties — these are non-negotiable:**
- Signature forgery must fail Block C
- Policy escalation must fail `checkPolicyAttenuation` and Block D
- Revoked chains must fail Block F
- Tampered DRs (modified payload) must fail Block C
- Chain splicing (wrong `prev_dr_hash`) must fail Block B
- Temporal violations (sub-DR `exp > parent exp`) must fail Block E

## RFC test vectors

`jcs_canonicalise` and `compute_cid` must pass all official RFC 8785 test vectors. These are non-negotiable:

```rust
#[test]
fn test_jcs_rfc8785_vector_1() {
    // From RFC 8785 Appendix B
    let input = r#"{"b":1,"a":2}"#;
    let expected = r#"{"a":2,"b":1}"#;
    assert_eq!(jcs_canonicalise(input).unwrap(), expected);
}
```

Canonicalisation divergence between implementations breaks cross-implementation JWT verification. These tests are a compatibility guarantee, not just unit tests.

## Running tests

```bash
# Rust — with coverage
cargo test
cargo tarpaulin --out Html   # requires cargo-tarpaulin

# Go — with race detector
go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out

# TypeScript
pnpm test                  # vitest run
pnpm test -- --reporter=verbose
```

## Test naming convention

Name tests to describe the property being tested, not the implementation:

```
# Good
TestSignatureForgeryShouldFail
TestPolicyEscalationRejectedAtIssuance
TestExpiredReceiptFailsTemporalBlock

# Bad
TestVerifyChain
TestIssueSubDelegation
TestBlock3
```

When a test fails, the name should tell you what property was violated.
