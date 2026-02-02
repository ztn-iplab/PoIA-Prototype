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
  --baseline app/data/baseline_experiments.csv
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

## Notes

- Data is stored in `/data/bank.db` (volume-backed)
- Passkeys require `https://poia.local`
- PoIA TTL is 60 seconds by default
- ZT-Authenticator PoIA approvals can be enabled per-user in Settings
