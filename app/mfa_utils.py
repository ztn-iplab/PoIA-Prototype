import base64
import io
import json
import secrets
import time
from typing import Any, Dict, Optional

import qrcode
import pyotp
from itsdangerous import URLSafeTimedSerializer

from .db import db_connect
from .settings import APP_RP_ID, MFA_ENROLL_SECRET, MFA_ENROLL_TTL_MINUTES, PUBLIC_BASE_URL

enroll_code_store: dict[str, tuple[Dict[str, Any], float]] = {}


def make_totp_qr(email: str, secret: str) -> Dict[str, str]:
    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="PoIA Bank")
    qr = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return {"qr_data_uri": f"data:image/png;base64,{encoded}", "manual_key": secret}


def mfa_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(MFA_ENROLL_SECRET)


def issue_enroll_token(payload: Dict[str, Any]) -> str:
    return mfa_serializer().dumps(payload)


def decode_enroll_token(token: str) -> Dict[str, Any]:
    return mfa_serializer().loads(token, max_age=MFA_ENROLL_TTL_MINUTES * 60)


def issue_enroll_code(payload: Dict[str, Any]) -> str:
    code = secrets.token_urlsafe(8)
    expires_at = time.time() + (MFA_ENROLL_TTL_MINUTES * 60)
    enroll_code_store[code] = (payload, expires_at)
    return code


def resolve_enroll_code(code: str) -> Optional[Dict[str, Any]]:
    entry = enroll_code_store.get(code)
    if not entry:
        return None
    payload, expires_at = entry
    if time.time() > expires_at:
        enroll_code_store.pop(code, None)
        return None
    return payload


def device_enrolled(user_id: int) -> bool:
    with db_connect() as conn:
        return (
            conn.execute(
                """
                SELECT device_keys.id
                FROM device_keys
                JOIN devices ON devices.id = device_keys.device_id
                WHERE devices.user_id = ? AND device_keys.rp_id = ?
                LIMIT 1
                """,
                (user_id, APP_RP_ID),
            ).fetchone()
            is not None
        )


def totp_needs_reset(user: Any, has_device: bool) -> bool:
    if not user:
        return True
    if user["otp_secret"] is None:
        return True
    if user["otp_email_label"] != user["email"]:
        return True
    if user["otp_rp_id"] and user["otp_rp_id"] != APP_RP_ID:
        return True
    return not has_device


def resolve_public_base_url(request) -> str:
    base_url = PUBLIC_BASE_URL or str(request.base_url)
    return base_url.rstrip("/")


def generate_qr_data_uri(payload: Dict[str, Any]) -> str:
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(json.dumps(payload))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def parse_date_to_epoch(value: str, end_of_day: bool = False) -> Optional[int]:
    if not value:
        return None
    try:
        parts = [int(part) for part in value.split("-")]
        if len(parts) != 3:
            return None
        year, month, day = parts
        if end_of_day:
            return int(time.mktime((year, month, day, 23, 59, 59, 0, 0, -1)))
        return int(time.mktime((year, month, day, 0, 0, 0, 0, 0, -1)))
    except Exception:
        return None


def build_statement_filters(request, user_id: int) -> tuple[str, list[Any], dict[str, str]]:
    account_id = request.query_params.get("account_id", "")
    txn_type = request.query_params.get("txn_type", "")
    date_from = request.query_params.get("date_from", "")
    date_to = request.query_params.get("date_to", "")

    where_clauses = ["accounts.user_id = ?"]
    params: list[Any] = [user_id]
    account_id_value: Optional[int] = None
    if account_id:
        try:
            account_id_value = int(account_id)
        except ValueError:
            account_id_value = None
    if account_id_value is not None:
        where_clauses.append("accounts.id = ?")
        params.append(account_id_value)
    if txn_type:
        where_clauses.append("transactions.txn_type = ?")
        params.append(txn_type)
    from_epoch = parse_date_to_epoch(date_from)
    if from_epoch is not None:
        where_clauses.append("transactions.created_at >= ?")
        params.append(from_epoch)
    to_epoch = parse_date_to_epoch(date_to, end_of_day=True)
    if to_epoch is not None:
        where_clauses.append("transactions.created_at <= ?")
        params.append(to_epoch)

    filters = {
        "account_id": account_id,
        "txn_type": txn_type,
        "date_from": date_from,
        "date_to": date_to,
    }
    return " AND ".join(where_clauses), params, filters
