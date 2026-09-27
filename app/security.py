import base64
import hashlib
import hmac
import secrets
import smtplib
import re
import sqlite3
import time
from email.message import EmailMessage

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .settings import MFA_OTP_PEPPER, SMTP_FROM, SMTP_HOST, SMTP_PASS, SMTP_PORT, SMTP_USER


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 150_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt_b64, digest_b64 = stored_hash.split("$")
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    iterations = int(iterations_str)
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def password_is_strong(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    return has_upper and has_lower and has_digit and has_symbol


def hash_reset_token(raw_token: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), raw_token.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_otp(code: str) -> str:
    data = (code + MFA_OTP_PEPPER).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_recovery_code(code: str) -> str:
    """Peppered digest for one-time TOTP backup/recovery codes, same
    construction as hash_otp -- these are short, high-entropy, single-use
    tokens delivered out of band (shown once in ZT-Authenticator), not
    memorized secrets, so a fast keyed hash is the right tool, matching the
    OTP hashing already used for login_challenges."""
    data = (code.strip().lower() + MFA_OTP_PEPPER).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def verify_p256_signature(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature_b64)
        key = serialization.load_der_public_key(public_key_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def authenticate_device_poll(request, user_id: int, device_id: int, rp_id: str) -> bool:
    """Authenticate one endpoint-bound read using the existing enrolled P-256 key."""
    from .db import db_connect

    nonce = request.headers.get("x-poia-poll-nonce", "")
    stamp = request.headers.get("x-poia-poll-time", "")
    signature = request.headers.get("x-poia-poll-signature", "")
    if not re.fullmatch(r"[0-9a-f]{48}", nonce) or not re.fullmatch(r"[0-9]{10}", stamp):
        return False
    now = int(time.time())
    if abs(now - int(stamp)) > 90 or len(signature) > 256 or "|" in rp_id:
        return False
    with db_connect() as conn:
        key = conn.execute(
            "SELECT k.public_key, k.key_type FROM device_keys k JOIN devices d ON d.id=k.device_id "
            "WHERE d.user_id=? AND k.device_id=? AND k.rp_id=?",
            (user_id, device_id, rp_id),
        ).fetchone()
        purpose = f"poll-v1:{request.url.path}:{user_id}:{stamp}"
        message = f"{nonce}|{device_id}|{rp_id}|{purpose}".encode("utf-8")
        if not key or key["key_type"] != "p256" or not verify_p256_signature(key["public_key"], message, signature):
            return False
        try:
            conn.execute("DELETE FROM device_poll_nonces WHERE expires_at < ?", (now,))
            conn.execute("INSERT INTO device_poll_nonces VALUES (?, ?, ?)",
                         (device_id, nonce, int(stamp) + 90))
        except sqlite3.IntegrityError:
            return False
    return True


def send_email(recipient: str, subject: str, body: str) -> bool:
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_USER:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(message)
        return True
    except Exception:
        return False
