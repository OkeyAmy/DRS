# DRS Practical Threat Model

## Scope

This threat model covers DRS source HEAD and controlled local or live-like
assessment runs. It does not cover production systems, third-party services, or
infrastructure outside the assessment operator's control.

## STRIDE Matrix

| STRIDE | DRS concern | Practical scenario | Evidence requirement | Current status |
|---|---|---|---|---|
| Spoofing | forged issuer DID, wrong tool server identity, or wrong admin token | malformed DID, wrong `tool_server`, wrong revoke token | HTTP status, response body, verifier log | Wrong admin token proven; DID/tool-server scenarios pending |
| Tampering | modified JWT, chain hash, or request body | signature mutation, chain-reference mutation, body-binding mismatch | verifier-only scenarios require explicit fail-closed code; middleware scenarios require 403 response plus handler-call evidence | Chain-reference tamper, signature tamper, body-binding detection, and Node HTTP middleware handler rejection proven |
| Repudiation | unclear audit trail for delegated action | successful verification with consent and regulatory context | sanitized verifier response and log excerpt | Consent/regulatory context proven in persona walkthrough |
| Information Disclosure | logs or metrics leak sensitive data | inspect rejection logs and `/metrics` output | sanitized excerpts showing no key material or sensitive payload leakage | Metrics sample captured; log leakage review pending |
| Denial of Service | oversized body, resolver slow path, replay storm | bounded local workload only | latency/error summary and resource observations | Not implemented: no bounded DoS scenario or latency/resource capture exists. |
| Elevation of Privilege | policy escalation, unauthorized revocation, or unsupported integration shape | forbidden tool, wrong admin token, policy mutation, Shape 2 walkthrough | observed denial or documented limitation | Forbidden tool denial and wrong admin token proven; policy mutation and Shape 2 pending |

## Validated Findings

No vulnerability finding is recorded from code reading alone. Findings move here
only after a controlled runtime scenario reproduces the behavior and includes a
safe recommended action.

## Open Questions

- How does Redis-backed nonce replay behave across two verifier instances under
  concurrent replay attempts?
- Which logs are necessary for audit reconstruction without exposing sensitive
  user data?
- Which bounded DoS scenario should be accepted for local assessment without
  conflating it with production load testing?
- Which benchmark thresholds should define pilot-ready versus production-ready
  deployment guidance?
