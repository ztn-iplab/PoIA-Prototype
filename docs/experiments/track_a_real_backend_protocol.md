# Track A Real-Backend Validation Protocol

This protocol implements the real WebAuthn and ZT-Authenticator cells in Track
A of `PoIA_Experimental_Validation_Plan.pdf`. It does not reuse the conference
dataset, the earlier 60-action pilot, or the verifier-only functional run.

## Evidence Boundary

Run one configuration in one directory. The WebAuthn and ZT-Authenticator
observations must never share a manifest. Each confirmatory legitimate-path
batch contains exactly 200 recorded authorization decisions. A successful
observation requires both an accept decision and the intended protected-state
transition. A denial, verifier error, timeout after RP receipt, or malformed RP
response remains in the denominator. Only a documented harness failure before
the request reaches the RP may be excluded.

Browser prompt cancellation before assertion submission is a client-aborted
interaction, not an RP authorization decision. Record it separately in the
operator log, retry it with a new intent, and do not represent it as one of the
200 issued RP decisions.

## Preflight

1. Commit the exact RP code to be measured; `git status --short` must be empty.
2. For ZT, commit the exact authenticator code; its repository must also be clean.
3. Record exact runtime versions and measure network RTT before creating the run.
4. Use synthetic accounts and objects only. Never enter production credentials.
5. Keep `POIA_TEST_MODE=false`; synthetic approval is not real-backend evidence.

Create the WebAuthn manifest:

```bash
python3 scripts/prepare_track_a_run.py \
  --configuration poia_webauthn \
  --batch-id webauthn-legitimate-01 \
  --seed 20260620 \
  --browser-or-client-runtime "Chrome <exact-version> on macOS" \
  --authenticator-platform "WebAuthn platform authenticator <details>" \
  --container-runtime "Docker Desktop <exact-version>" \
  --network-rtt-ms <measured-rtt> \
  --database-backend "SQLite <exact-version>"
```

For ZT, change the configuration and add the authenticator repository:

```bash
python3 scripts/prepare_track_a_run.py \
  --configuration poia_zt_authenticator \
  --batch-id zt-legitimate-01 \
  --seed 20260620 \
  --authenticator-repo ../ZT-Authenticator \
  --browser-or-client-runtime "ZT mobile client <version/platform>" \
  --authenticator-platform "ZT-Authenticator P-256 <device/runtime>" \
  --container-runtime "Docker Desktop <exact-version>" \
  --network-rtt-ms <measured-rtt> \
  --database-backend "SQLite <exact-version>"
```

Preparation refuses a dirty RP or authenticator repository. It prints a local
`run.env`; source those values into the application environment using the
container-visible manifest path shown there, then start the application with
`./run.sh --build`.

## Execution

For WebAuthn, enroll the real platform passkey, select WebAuthn authorization,
and issue 200 synthetic protected operations through the normal UI. For ZT,
enroll the real mobile P-256 key, select ZT authorization, and approve 200 new
intents in the authenticator. Do not use `/api/poia/test/approve`.

The production gate records one linked evidence bundle per decision:

- `decisions/decisions.jsonl`: decision, reason, backend, timing, and hashes.
- `requests/`: pseudonymized approved and requested intent evidence.
- `state_snapshots/`: linked before/after protected-state evidence.
- `timings/`: raw clock source, timestamps/counters, and measured latency.

Authenticator failures after a valid intent reaches the RP, including expiry,
nonce/RP/hash mismatch, replay, enrollment failure, invalid signature, and user
denial, are recorded as rejections. Raw signatures, cookies, tokens, private
keys, and direct identifiers are never written.

After each practical batch, inspect progress:

```bash
python3 scripts/track_a_run_status.py experiments/track_a/raw/<run-id>
```

Stop at exactly 200. The status command reports remaining observations,
duplicates, and missing evidence bundles. Preserve any anomaly; do not delete
or rerun it merely because it changes the result.

## Freeze And Analyze

At 200 observations, stop the application, make a read-only copy of the raw run,
compute checksums, and review every artifact for the sensitive-data policy.
Generate the result only with the frozen run:

```bash
python3 scripts/analyze_track_a.py experiments/track_a/raw/<run-id>
```

The final report must include counts, proportions with Wilson 95% intervals,
rejection reasons, unauthorized state transitions, and latency median, IQR,
P95, and P99. WebAuthn and ZT findings remain separate until the manuscript
table explicitly compares their independently archived runs.
