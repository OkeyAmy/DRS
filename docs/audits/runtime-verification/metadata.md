# DRS Metadata Assessment

## Purpose

This assessment separates what DRS can prove from what a regulator, auditor, or
lawyer must validate outside DRS. Regulatory metadata is useful only when its
evidence boundary is explicit.

## Validation Classes

| Class | What DRS can validate | What DRS cannot validate |
|---|---|---|
| Cryptographic binding | The metadata was inside a signed receipt verified by Ed25519 and hash-chain checks. | Whether the real-world statement is true. |
| Schema validation | Field names, types, enum values, formats, and ranges. | Whether a business chose the right value. |
| Policy validation | Local allowlists, retention ranges, consent method requirements, and policy-disclosure hash equality. | Whether the policy is legally sufficient. |
| External truth | Nothing directly; DRS can point to external evidence. | Legal compliance, SOC 2 certification, or actual consent occurrence without external proof. |

## Framework Registry

The persona walkthrough uses canonical framework identifiers, not marketing
labels. Display labels such as “EU AI Act” or “SOC 2” are rendered only for
humans after validation.

| ID | Display label | Source | DRS validation boundary |
|---|---|---|---|
| `eu-ai-act-art12` | EU AI Act Article 12 record-keeping | Regulation (EU) 2024/1689, EUR-Lex: `https://data.europa.eu/eli/reg/2024/1689/oj` | DRS proves the label was asserted and not tampered with; it does not prove the deployment is subject to or compliant with Article 12. |
| `eu-ai-act-art13` | EU AI Act Article 13 transparency | Regulation (EU) 2024/1689, EUR-Lex: `https://data.europa.eu/eli/reg/2024/1689/oj` | DRS proves the label was asserted and not tampered with; transparency compliance needs product/process evidence. |
| `soc2-security` | SOC 2 Security trust service criterion | AICPA Trust Services Criteria: `https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022` | DRS proves the label was asserted and not tampered with; SOC 2 evidence requires an independent service-auditor examination. |
| `soc2-availability` | SOC 2 Availability trust service criterion | AICPA Trust Services Criteria | Same boundary as above. |
| `soc2-processing-integrity` | SOC 2 Processing Integrity trust service criterion | AICPA Trust Services Criteria | Same boundary as above. |
| `soc2-confidentiality` | SOC 2 Confidentiality trust service criterion | AICPA Trust Services Criteria | Same boundary as above. |
| `soc2-privacy` | SOC 2 Privacy trust service criterion | AICPA Trust Services Criteria | Same boundary as above. |

## Field-Level Rules

| Metadata field | Validation implemented in walkthrough | Evidence class | Failure evidence |
|---|---|---|---|
| `drs_regulatory.frameworks` | Each value must exist in the framework registry. | Schema + policy | `metadata.test.ts` rejects `EU AI Act` and `SOC 2` display labels as raw ids. |
| `drs_regulatory.risk_level` | Must be one of `unacceptable`, `high`, `limited`, `minimal`. | Schema | `metadata.test.ts` rejects `medium`. |
| `drs_regulatory.retention_days` | Must be a non-negative integer. | Schema | `metadata.test.ts` rejects `-1`. |
| `drs_consent.method` | Must be one of `explicit-ui-click`, `explicit-ui-checkbox`, `api-delegation`, `operator-policy`. | Schema + policy | `metadata.test.ts` rejects `explicit-click`. |
| `drs_consent.session_id` | Must start with `sess:` for this assessment. | Schema + correlation key | `metadata.test.ts` rejects missing prefix. |
| `drs_consent.policy_hash` | Must equal SHA-256 of the human-readable disclosure text used in the example. | Policy validation | `metadata.test.ts` rejects an all-zero hash. |
| `drs_root_type` | Must be `human` for the persona walkthrough and must expose consent. | Schema + structural policy | `metadata.ts` reports missing or non-human root type. |

## Current Evidence

The executable evidence is:

```bash
pnpm --filter drs-persona-walkthrough test
pnpm --filter drs-persona-walkthrough capture -- .local/drs-assessment/responses
```

The capture output includes a `metadataValidation` object for each scenario. It
states whether metadata passed schema/policy validation and repeats the external
truth warning.

## Non-Overclaim Rule

Assessment prose must not say “DRS is EU AI Act compliant”, “DRS is SOC 2
certified”, or equivalent. The strongest supported statement from the current
walkthrough is:

> DRS cryptographically binds asserted regulatory metadata and validates it
> against an assessment-local schema/policy registry. External compliance still
> requires separate legal, product, and auditor evidence.
