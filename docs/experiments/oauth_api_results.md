# Experiment 7: OAuth/API Integration Results

## Confirmatory Run

- Run ID: `oauth-api-confirmatory-01`
- Frozen implementation commit: `9cbb44907852492bfd3d254e55286ffbfeac319a`
- Trials per mode and scenario: 200
- Action requests: 1,600
- Integration: FastAPI TestClient and SQLite protected state

## Security Outcome

OAuth-only accepted all 800 requests. This included 600/600 cross-action,
target-object, and scope-parameter substitutions, and every accepted attack
produced a protected-state row. OAuth plus PoIA accepted all 200 exact requests
and rejected all 600 substitutions; none of the rejected requests changed
protected state. All 1,600 decisions and denial reasons matched the fixed
reference outcomes.

| Mode | Exact accepted | Substitutions executed | Substitutions rejected | False rejects |
|---|---:|---:|---:|---:|
| OAuth-only broad token | 200/200 | 600/600 | 0/600 | 0 |
| OAuth plus PoIA | 200/200 | 0/600 | 600/600 | 0 |

Action substitutions were denied as `action_mismatch`; target and parameter
substitutions were denied as `scope_mismatch`.

## Endpoint Timing

The median exact-request action-endpoint time was 2.2777 ms for OAuth-only and
2.3744 ms for OAuth plus PoIA, a median difference of 0.0967 ms. Corresponding
P95 values were 3.0980 ms and 3.1899 ms. These local TestClient/SQLite timings
exclude token issuance, intent creation, user approval, physical signing,
browser or handset interaction, and network transit.

## Interpretation

The result shows composition at the prototype resource-server boundary: broad
token authority remained valid, while PoIA constrained its use to one approved
operation. It does not show an OAuth implementation defect, OAuth protocol
conformance, authorization-server security, or real-authenticator latency. The
approved proof was supplied by an in-process test fixture.

## Reproduction

```bash
python scripts/run_oauth_api_integration.py \
  --run-id oauth-api-confirmatory-reproduction-01
```

Verify the checksum list and use the database-backed `state_changed` field in
the trial CSV as the execution outcome; do not infer execution from HTTP status
alone.
