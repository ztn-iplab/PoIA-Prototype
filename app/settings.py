import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("POIA_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "bank.db"

APP_RP_ID = "poia-demo-bank"
INTENT_TTL_SECONDS = 60
POIA_TRANSFER_THRESHOLD = 100.0
POIA_WITHDRAW_THRESHOLD = 500.0
SESSION_SECRET = os.getenv("POIA_SESSION_SECRET", "dev-only-secret")
ADMIN_EMAIL = os.getenv("POIA_ADMIN_EMAIL", "admin@poia.demo").strip().lower()
ADMIN_PASSWORD = os.getenv("POIA_ADMIN_PASSWORD", "")
POIA_ENABLED = os.getenv("POIA_ENABLED", "true").lower() == "true"
POIA_TEST_MODE = os.getenv("POIA_TEST_MODE", "false").lower() == "true"
POIA_EXPERIMENT_MODE = os.getenv("POIA_EXPERIMENT_MODE", "false").lower() == "true"

# Known-insecure literal values that must never reach a network-reachable
# deployment. Enforcement for SESSION_SECRET lives in app/main.py, at the one
# place the app actually becomes network-reachable (SessionMiddleware
# construction) -- not here, since app.settings is imported by ~40 offline
# analysis/experiment scripts (scripts/*.py) that never start a server and were
# never exposed to session-forgery risk in the first place; gating here would
# force every such script to also set POIA_TEST_MODE for no security benefit.
INSECURE_SESSION_SECRETS = {
    "",
    "dev-only-secret",
    "change-me",
    "change-me-in-local-demo",
}

_INSECURE_ADMIN_PASSWORDS = {"replace-with-a-unique-random-admin-password"}
if ADMIN_PASSWORD in _INSECURE_ADMIN_PASSWORDS and not POIA_TEST_MODE:
    raise RuntimeError(
        "POIA_ADMIN_PASSWORD is set to the documentation placeholder value from "
        ".env.example. Set a real, unique admin password before starting outside "
        "of POIA_TEST_MODE."
    )
# Referent-State Integrity: re-verify referenced content (e.g. a beneficiary's bank
# details) against what was committed at signing time, immediately before execution.
# Default true (the strengthened design). Set false to reproduce the legacy
# resolve-by-reference behavior for paired evaluation, matching the Tamarin
# D_RSI vs D_Legacy comparison in formal-models/referent_state_integrity.spthy.
RSI_ENABLED = os.getenv("RSI_ENABLED", "true").lower() == "true"
# k-of-n Independent Commitment Confinement: require k of n independent commitment
# roots to agree on referenced content before an intent may proceed to signing.
# Default true (the strengthened design). Set false to reproduce the legacy
# single-root behavior for paired evaluation, matching the Tamarin K1 vs K2
# comparison in formal-models/kofn_confinement.spthy.
KOFN_ENABLED = os.getenv("KOFN_ENABLED", "true").lower() == "true"
KOFN_K = int(os.getenv("KOFN_K", "2"))
KOFN_N = int(os.getenv("KOFN_N", "2"))
if (KOFN_K, KOFN_N) != (2, 2):
    raise ValueError("Only the two-function consistency check (KOFN_K=2, KOFN_N=2) is implemented.")
MFA_ENROLL_SECRET = os.getenv("MFA_ENROLL_SECRET", SESSION_SECRET)
MFA_ENROLL_TTL_MINUTES = 10
TOTP_INTERVAL_SECONDS = 30
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://poia.local")
POIA_AUTH_BASE_URLS = [
    value.strip().rstrip("/")
    for value in os.getenv("POIA_AUTH_BASE_URLS", "").split(",")
    if value.strip()
]
MFA_OTP_PEPPER = os.getenv("MFA_OTP_PEPPER", MFA_ENROLL_SECRET)
RESET_TOKEN_TTL_SECONDS = 900
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@poia.demo")
WEB_RP_ID = os.getenv("WEB_RP_ID", "poia.local")
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "https://poia.local")
