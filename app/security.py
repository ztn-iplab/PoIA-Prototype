import base64
import hashlib
import hmac
import secrets
import smtplib
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
