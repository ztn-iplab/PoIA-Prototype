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
POIA_ENABLED = os.getenv("POIA_ENABLED", "true").lower() == "true"
MFA_ENROLL_SECRET = os.getenv("MFA_ENROLL_SECRET", SESSION_SECRET)
MFA_ENROLL_TTL_MINUTES = 10
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://poia.local")
MFA_OTP_PEPPER = os.getenv("MFA_OTP_PEPPER", MFA_ENROLL_SECRET)
RESET_TOKEN_TTL_SECONDS = 900
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@poia.demo")
WEB_RP_ID = os.getenv("WEB_RP_ID", "poia.local")
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "https://poia.local")
