# Human Consent Records

When a human grants authority, the root DR must include a `drs_consent` record proving the user saw and approved the policy in human-readable form.

## Why it matters

The `policy` field in a DR is machine-readable JSON. A user who clicks "Allow" on a form that shows them `{"max_cost_usd":50}` has not meaningfully consented — they have not understood what they approved.

The `drs_consent.policy_hash` is the SHA-256 of the **human-readable text** the user actually saw. Auditors can verify that the consent UI displayed legible information, not raw JSON.

## Generating the human-readable text

Use the SDK's `translatePolicy` function:

```typescript
import { translatePolicy } from '@drs/sdk';

const humanText = translatePolicy({
  allowed_tools: ['web_search', 'write_file'],
  max_cost_usd: 50.00,
  pii_access: false,
  write_access: false,
}, { locale: 'en-GB' });

// Output:
// Research Agent wants permission to:
// ✓  Search the web
// ✓  Save files to your workspace
// ✗  Cannot access personal data
// ✗  Cannot spend more than £50.00
```

Or via CLI:
```bash
echo '{"allowed_tools":["web_search"],"max_cost_usd":50}' | pnpm exec drs translate --locale en-GB
```

## Computing the policy hash

```typescript
import { computeChainHash } from '@drs/sdk';

// Hash the text the user saw — not the policy JSON
const policyHash = computeChainHash(humanText);
// "sha256:a1b2c3..."
```

## Building the consent record

```typescript
import { issueRootDelegation, computeChainHash, translatePolicy } from '@drs/sdk';

const policy = {
  allowed_tools: ['web_search'],
  max_cost_usd: 50.00,
  pii_access: false,
};

// 1. Translate for the user
const humanText = translatePolicy(policy, { locale: 'en-GB' });

// 2. Show humanText in your consent UI
// await showConsentDialog(humanText);  — user clicks Allow

// 3. Record their consent
const rootDR = await issueRootDelegation({
  // ... other params ...
  policy,
  rootType: 'human',
  consent: {
    method: 'explicit-ui-click',
    timestamp: new Date().toISOString(),
    session_id: 'sess:' + crypto.randomUUID(),
    policy_hash: computeChainHash(humanText),
    locale: 'en-GB',
  },
});
```

## Consent methods

| Value | When to use |
|---|---|
| `explicit-ui-click` | User clicked an "Allow" or "I agree" button |
| `explicit-ui-checkbox` | User checked a checkbox next to each permission |
| `api-delegation` | Programmatic delegation (organisation-rooted, no human interaction) |
| `operator-policy` | Automated-system root — no human involved |

## Machine-rooted delegations

If `rootType` is `"automated-system"` or `"organisation"`, the `consent` field is optional. These root types are used by operators delegating to their own agents without per-session human approval.

```typescript
const rootDR = await issueRootDelegation({
  // ...
  rootType: 'automated-system',
  // consent: not required
});
```
