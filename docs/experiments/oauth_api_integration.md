# Experiment 7: OAuth/API Integration

## Goal

This experiment shows that PoIA complements delegated authorization rather than
replacing it. OAuth answers whether a token has a broad delegated permission,
such as `key:rotate`. PoIA answers whether the current high-risk API request is
the exact intent the user approved.

The experiment compares:

- OAuth-only authorization
- OAuth plus PoIA intent-bound proof

## Threat Model

The attacker has a valid OAuth token with a broad enough scope to call a
high-risk endpoint. The attacker does not have the user's PoIA signing key and
cannot produce a valid proof over a changed intent.

This models cross-action and parameter tampering cases where a bearer token is
still valid, but the request no longer matches what the user intended.

## Implementation Location

The experiment is implemented in:

```text
scripts/run_oauth_api_integration.py
```

Generated artifacts are written to:

```text
experiments/oauth_api_integration/
```

The main files are:

- `oauth_api_summary.json`: aggregate results
- `oauth_api_trials.csv`: trial-by-trial decisions
- `oauth_api_table.md`: paper-friendly comparison table

## Simulated OAuth Token

The script creates a signed token-like claim set:

```json
{
  "sub": "user-1",
  "aud": "api.example",
  "scope": ["admin:write", "key:rotate"],
  "exp": 1900000000
}
```

For reproducibility, this is represented with HMAC rather than a full JWT
library. That keeps the experiment dependency-free while preserving the relevant
security property for the comparison: the token claims are integrity-protected.

The OAuth-only verifier checks:

1. The token signature is valid.
2. The required API scope is present.

If both are true, OAuth-only accepts the request.

## PoIA Intent

The approved PoIA intent is:

```json
{
  "action": "rotate_key",
  "scope": {
    "key_id": "kms-key-77",
    "project": "prod-payments",
    "region": "ap-northeast-1"
  },
  "context": {
    "rp_id": "api.example",
    "user_id": "user-1",
    "oauth_audience": "api.example"
  },
  "constraints": {
    "nonce": "oauth-poia-nonce",
    "expires_at": 1900000000
  }
}
```

The proof is an HMAC over the canonical JSON form of that intent. In the real
PoIA deployment this corresponds to a device-bound signature, such as WebAuthn
or ZT-Authenticator. HMAC is used here only as a local reproducibility stand-in
for "a proof that cannot be forged for a changed intent."

## Canonicalization

Both token claims and PoIA intents are serialized with:

```python
json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

This means field order and whitespace do not affect verification. The verifier
compares canonical bytes for the request intent and approved intent.

## Scenarios

| Scenario | Request Change | OAuth-only Expected | OAuth + PoIA Expected |
|---|---|---:|---:|
| `legitimate_api_call` | None | Accept | Accept |
| `cross_action_token_misuse` | `action` changes from `rotate_key` to `delete_key` | Accept | Reject |
| `api_tampering_wrong_key` | `scope.key_id` changes from `kms-key-77` to `kms-root` | Accept | Reject |
| `api_tampering_wrong_project` | `scope.project` changes from `prod-payments` to `prod-identity` | Accept | Reject |

The key point is that the token scope remains sufficient in all attack
scenarios. OAuth-only therefore accepts them because it sees a valid bearer token
with `key:rotate`. OAuth + PoIA rejects them because the request intent no
longer equals the approved intent.

## Verifier Logic

OAuth-only:

```text
valid token signature?
required scope present?
accept
```

OAuth + PoIA:

```text
valid token signature?
required scope present?
valid PoIA proof over approved intent?
request intent equals approved intent after canonicalization?
accept
```

Failure reasons are recorded as:

- `invalid_token`
- `insufficient_scope`
- `invalid_poia_proof`
- `intent_mismatch`
- `oauth_scope_authorized`
- `oauth_and_poia_authorized`

## Metrics

The experiment records:

- accepted attempts
- correct decision rate
- cross-action token misuse success rate
- API tampering rejection rate
- verification overhead in milliseconds
- denial/acceptance reason

## Reproduce

```bash
python3 scripts/run_oauth_api_integration.py --trials 60 --out-dir experiments/oauth_api_integration
```

Then inspect:

```bash
cat experiments/oauth_api_integration/oauth_api_table.md
```

For trial-level evidence:

```bash
head -20 experiments/oauth_api_integration/oauth_api_trials.csv
```

## Interpretation

If the experiment is working as intended:

- OAuth-only accepts the legitimate request and the tampered requests.
- OAuth + PoIA accepts only the legitimate request.
- Tampered requests are rejected with `intent_mismatch`.
- The overhead remains small because the local experiment measures only
  canonicalization and proof verification, not human approval time.

This supports the paper argument that PoIA can sit behind existing OAuth
authorization and add intent-level enforcement at high-risk endpoints.
