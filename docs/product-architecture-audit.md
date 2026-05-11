# Product Architecture Audit

## Current Product Flow

DRS ships as three separable product surfaces:

1. **SDK issues receipts and bundles.** The application or agent uses
   `@okeyamy/drs-sdk` to issue delegation receipts, issue invocation receipts,
   and assemble a `ChainBundle`.
2. **Verifier evaluates trust.** The application sends the bundle plus the
   exact request body to `drs-verify` `/verify`. The verifier validates chain
   structure, signatures, policy attenuation, time bounds, revocation, replay,
   and optional request-body binding.
3. **Application middleware enforces.** The tool server uses reusable
   middleware to reject missing bundles, invalid chains, verifier outages, and
   body-binding mismatches before its handler executes.

The intended path is:

```text
SDK -> bundle -> verifier -> app enforcement
```

## Boundary Decision

`drs-verify` remains verifier-only. It is not a transparent forwarding gateway
and should not own application routing, upstream retries, request mutation, or
tool execution.

For v1 productization, enforcement lives inside the Node/Express/Fastify-style
application middleware because it can compare the verifier result against the
same parsed body the handler will execute.

## Shipping Shape

- Use `@okeyamy/drs-sdk` to issue root/sub-delegation receipts and invocation
  bundles.
- Use `@drs/mcp-server` HTTP middleware to enforce DRS at Node app boundaries.
- Use `drs-verify` as the trust engine behind `/verify`.
- Treat a forwarding gateway as a later `drs-gateway` milestone, not an
  implicit behavior of `drs-verify`.
