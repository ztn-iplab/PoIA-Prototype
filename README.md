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

## Notes

- Data is stored in `/data/bank.db` (volume-backed)
- Passkeys require `https://poia.local`
- PoIA TTL is 60 seconds by default
- ZT-Authenticator PoIA approvals can be enabled per-user in Settings
