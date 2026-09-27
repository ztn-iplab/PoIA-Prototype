# OAuth/API Integration Implementation Guide

## Purpose and Boundary

Experiment 7 tests whether PoIA can add exact-operation enforcement behind a
broad delegated bearer-token check. It exercises the prototype's real FastAPI
routes and SQLite protected state. The opaque token and `high_risk_api` scope
model the resource-server semantics relevant to token misuse; this is not an
OAuth authorization-server or protocol-conformance implementation.

## Request Flow

1. An authenticated user calls `/api/poia/experiment/token/issue`.
2. The server returns a fresh opaque bearer token and stores only its SHA-256
   hash, principal, broad scope, intended action, and expiration.
3. In `oauth_only` mode, the high-risk action route validates the token and
   accepts any supported action and scope under that broad authority.
4. In `oauth_plus_poia` mode, the user first creates an exact intent through
   `/api/poia/experiment/token/intent/start`.
5. The action route validates the token, reserves the one-time proof, compares
   the approved and requested action, scope, principal, RP, and constraints,
   and writes the protected operation only after all checks succeed.

The confirmatory harness inserts an approved proof through an in-process test
fixture. It deliberately excludes physical WebAuthn and ZT-Authenticator
interaction while retaining the production API execution gate.

## Fixed Workload

For each mode, the harness sends 200 fresh trials of an exact request,
cross-action substitution, target-object substitution, and scope-parameter
substitution. Every trial uses a fresh valid token. PoIA trials also use a fresh
intent, nonce, proof record, and object identifier.

The authoritative execution measure is the row-count change in
`experiment_api_operations` before and after each action request. The CSV never
contains bearer tokens, cookies, raw signatures, or reusable proofs.

## Reproduce

```bash
python scripts/run_oauth_api_integration.py \
  --run-id oauth-api-confirmatory-reproduction-01
```

Confirmatory execution requires a clean Git tree and exactly 200 trials per
cell. Inspect the manifest, 1,600-row trial CSV, summary, paper table, and
SHA-256 checksum list under `experiments/oauth_api_integration/`.

See `oauth_api_preregistration.md` for fixed hypotheses and
`oauth_api_results.md` for the reviewed result and interpretation limits.
