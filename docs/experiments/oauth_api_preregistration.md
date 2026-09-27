# Experiment 7 Pre-registration: OAuth/API Integration

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Claim Under Test

An intent-bound PoIA gate complements broad delegated bearer-token authorization
by rejecting high-risk API requests that remain token-authorized but differ from
the operation approved by the user.

## Integration Boundary

Exercise the FastAPI and SQLite implementation at:

- `POST /api/poia/experiment/token/issue`;
- `POST /api/poia/experiment/token/intent/start`; and
- `POST /api/poia/experiment/token/action`.

The server issues a fresh opaque bearer token, stores only its SHA-256 hash, and
assigns broad `high_risk_api` authority. This models the resource-server
semantics relevant to token misuse. It is not an OAuth authorization-server,
JWT interoperability, consent, refresh-token, or protocol-conformance test.

## Fixed Modes and Scenarios

Compare `oauth_only` and `oauth_plus_poia` for 200 fresh trials of each:

1. exact `deploy_config` request;
2. cross-action substitution to `api_key_rotate`;
3. target-object substitution; and
4. scope-parameter substitution.

Total action requests: 2 modes x 4 scenarios x 200 = 1,600. Every request has a
valid, unexpired token with sufficient broad authority. OAuth-only is expected
to accept all four scenarios. OAuth plus PoIA is expected to accept only the
exact request and reject substitutions with the production semantic mismatch
reason.

## PoIA Test Proof

For each PoIA trial, create an intent through the HTTP route and insert a fresh
approved proof through the in-process test fixture before calling the production
execution endpoint. This isolates the API integration and execution gate from
physical WebAuthn or ZT-Authenticator interaction. Results must therefore be
reported as server-side integration evidence, not signing-backend evidence.

## Measurements

- prohibited protected-state transitions (attack success);
- legitimate protected-state transitions;
- correct and incorrect decisions;
- semantic denial reason;
- action-endpoint latency (median, IQR, P95, P99); and
- additional exact-request endpoint latency for OAuth plus PoIA versus
  OAuth-only.

The database row count before and after every action request is authoritative
for execution. HTTP status alone is insufficient.

## Confirmatory Controls

- Fixed 200 trials per mode and scenario.
- Fresh token, intent, nonce, and object identifiers per trial.
- Clean Git tree and unique run identifier required.
- No bearer token, cookie, private key, raw signature, or reusable proof is
  written to the public artifact.
- Manifest, redacted trial rows, summary, table, and SHA-256 checksums preserved.
- Existing 60-trial HMAC simulation artifacts are exploratory and excluded.

## Interpretation Limit

The experiment tests the prototype resource-server integration and protected
state transition on one local process and SQLite database. It does not establish
OAuth protocol conformance, multi-resource token exchange, authorization-server
security, physical-authenticator latency, or resistance to endpoint compromise.
