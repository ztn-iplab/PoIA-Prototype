# Proof-of-Intent Authentication (PoIA) Banking Prototype

This prototype is an internet banking app that demonstrates PoIA.
High-risk actions require a cryptographic proof of intent that binds approval
to a specific action, scope, context, and time window. PoIA uses passkeys
(WebAuthn) for intent signing and can optionally integrate ZT-Authenticator.

## Quick start (Podman + HTTPS)

1) Run the automated setup script:

   ./run.sh

2) Open the app:

   https://poia.local

The script:
- Maps `poia.local` to your current LAN IP
- Generates a TLS cert signed by the ZT-IAM CA
- Starts the app + nginx + Mailpit via Podman

## Quick start (local dev, no TLS)

1) Create a virtual environment and install dependencies:

   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

2) Run the server:

   uvicorn app.main:app --reload

3) Open the app:

   http://127.0.0.1:8000

Note: Passkeys require HTTPS, so WebAuthn won’t work in this mode.

## MFA (ZT-Authenticator app)

This app generates a TOTP enrollment QR code locally. Scan it with the
ZT-Authenticator mobile app (or any standard TOTP app) to enroll.

## Container notes

- The HTTPS entrypoint is via nginx and `https://poia.local`
- Mailpit is exposed at `http://127.0.0.1:8027` (web UI)

## Demo flow

- Sign up or log in (admin: admin@poia.demo / Admin!Secure12345)
- Add beneficiaries and initiate transfers
- High-risk actions trigger PoIA (passkey) inline on the action page
- Admin views (audit + MFA metrics) are protected by PoIA
- PoIA approvals are recorded in audit logs

## Research instrumentation (PoIA experiments)

The PoIA prototype logs experiment telemetry to support reproducible security,
performance, and usability evaluation. Logs are written to:

- `app/data/poia_experiments.csv`

### Journal experiment package

The expanded journal experiment suite is documented in:

```
docs/experiments/README.md
```

That guide explains the goal, assumptions, commands, generated files, and how to
read the results for all ten experiments. The most important deep dives are:

- `docs/experiments/experiment_designs.md` — explains the research question,
  implementation, metrics, and interpretation for each experiment.
- `docs/experiments/oauth_api_integration.md` — explains how OAuth-only and
  OAuth + PoIA are simulated and compared.
- `docs/experiments/tamarin_formal_verification.md` — explains
  `tamarin/poia_protocol.spthy`, the lemmas, batch proof reproduction, and
  interactive Tamarin testing.

The Tamarin model itself is available at:

```
tamarin/poia_protocol.spthy
```

Run the formal proof from the repository root:

```
./scripts/run_tamarin_poia.sh
```

### What is captured
- Intent creation, approval, denial, and execution events
- WebAuthn vs ZT-Authenticator approval method
- Approval latency (ms)
- TTL/expiry outcomes and replay attempts
- UX steps (modal loaded, passkey prompt, approval outcome)

### Scenario tagging
To attribute events to an attack scenario, include a `scenario` query
parameter when launching the PoIA intent modal. Example:

```
https://poia.local/transfer?poia_intent=...&scenario=replay
```

The scenario label is stored in the metrics CSV for analysis.

### Analysis script
Run the bundled analyzer to produce success rates and latency summaries:

```
python3 scripts/analyze_poia_metrics.py --poia app/data/poia_experiments.csv
```

Provide a baseline CSV (if collected separately) to compute comparison tables:

```
python3 scripts/analyze_poia_metrics.py \
  --poia app/data/poia_experiments.csv \
  --baseline-csv app/data/baseline_experiments.csv
```

### One-command experiment suite
Run attack scenarios, collect baseline latency, and auto-generate comparison tables:

```
python3 scripts/run_experiment_suite.py \
  --base-url https://poia.local \
  --db-path .tmp_bank.db \
  --poia-csv app/data/poia_experiments.csv \
  --trials 30 --insecure
```

## Experiment protocol

1) **Security effectiveness**
   - Run attack scenarios (replay, relay_phishing, session_misuse, intent_substitution).
   - Record attempts by adding `scenario=` to the intent URL.

2) **Functional correctness**
   - Trigger action/scope mismatch and expired intent cases.
   - Verify that all mismatches are rejected.

3) **Performance overhead**
   - Measure baseline actions without PoIA.
   - Measure PoIA approvals and compare median/p95/max latency.

4) **Usability impact**
   - Track completion time and error rate (from telemetry).
   - Collect perceived clarity scores via short surveys.

5) **Auditability**
   - Verify each executed action has intent linkage (intent_id, rp_id, device_id).
   - Compare with baseline session-only logging.

