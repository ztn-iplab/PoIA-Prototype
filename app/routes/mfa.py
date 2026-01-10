import json
import secrets
import time
from typing import Any, Dict

import pyotp
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from itsdangerous import BadSignature, SignatureExpired

from ..core import get_current_user, log_audit, log_mfa_event, render, require_login
from ..db import db_connect
from ..mfa_utils import (
    decode_enroll_token,
    device_enrolled,
    generate_qr_data_uri,
    issue_enroll_code,
    issue_enroll_token,
    resolve_enroll_code,
    resolve_public_base_url,
    totp_needs_reset,
)
from ..security import hash_otp, verify_p256_signature
from ..settings import APP_RP_ID, MFA_ENROLL_TTL_MINUTES
from ..webauthn_utils import user_has_webauthn

router = APIRouter()


@router.get("/mfa/setup", response_class=HTMLResponse)
def mfa_setup(request: Request) -> HTMLResponse:
    if not request.session.get("pre_mfa_user_id") and not get_current_user(request):
        return RedirectResponse(url="/login", status_code=302)
    pre_mfa_user_id = request.session.get("pre_mfa_user_id")
    user_id = pre_mfa_user_id or request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user["otp_secret"] and device_enrolled(user_id) and not (user["otp_rp_id"] and user["otp_rp_id"] != APP_RP_ID):
        if pre_mfa_user_id:
            return RedirectResponse(url="/mfa/verify", status_code=302)
        return RedirectResponse(url="/dashboard", status_code=302)
    return render(request, "setup_totp.html", {})


@router.get("/mfa/choose", response_class=HTMLResponse)
def mfa_choose(request: Request) -> HTMLResponse:
    user_id = request.session.get("pre_mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    has_totp = bool(user and user["otp_secret"]) and device_enrolled(user_id)
    has_passkey = user_has_webauthn(user_id)
    if has_totp and has_passkey:
        return render(request, "mfa_choice.html", {})
    if has_passkey:
        return RedirectResponse(url="/mfa/passkey", status_code=302)
    return RedirectResponse(url="/mfa/verify", status_code=302)


@router.get("/api/mfa/setup")
def api_mfa_setup(request: Request) -> Response:
    user_id = request.session.get("pre_mfa_user_id") or request.session.get("user_id")
    if not user_id:
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)

    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return Response(content=json.dumps({"error": "not_found"}), media_type="application/json", status_code=404)
        has_device = device_enrolled(user_id)
        reset_required = totp_needs_reset(user, has_device)

        pending = conn.execute("SELECT * FROM pending_totp WHERE user_id = ?", (user_id,)).fetchone()
        if pending and pending["expires_at"] < int(time.time()):
            conn.execute("DELETE FROM pending_totp WHERE id = ?", (pending["id"],))
            pending = None

        if not reset_required:
            if pending:
                conn.execute("DELETE FROM pending_totp WHERE id = ?", (pending["id"],))
            return Response(content=json.dumps({"message": "TOTP already configured."}), media_type="application/json")

        if pending:
            secret = pending["secret"]
            pending_id = pending["id"]
        else:
            secret = pyotp.random_base32()
            expires_at = int(time.time()) + (MFA_ENROLL_TTL_MINUTES * 60)
            cur = conn.execute(
                "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, secret, user["email"], expires_at),
            )
            pending_id = cur.lastrowid

    enroll_token = issue_enroll_token(
        {"pending_id": pending_id, "user_id": user_id, "email": user["email"], "rp_id": APP_RP_ID}
    )
    base_url = resolve_public_base_url(request)
    api_base = base_url + "/api/auth"
    payload = {
        "type": "zt_totp_enroll",
        "email": user["email"],
        "rp_id": APP_RP_ID,
        "rp_display_name": "PoIA Bank",
        "issuer": "PoIA Bank",
        "account_name": user["email"],
        "device_label": "ZT-Authenticator Device",
        "enroll_token": enroll_token,
        "api_base_url": api_base,
        "base_url": api_base,
        "enroll_url": api_base + "/enroll",
    }
    qr_code = generate_qr_data_uri(payload)
    code = issue_enroll_code(payload)
    manual_url = f"{base_url}/api/auth/enroll-code/{code}"
    response = {"qr_code": qr_code, "manual_key": manual_url, "reset_required": True}
    return Response(content=json.dumps(response), media_type="application/json")


@router.get("/api/mfa/enroll-code/{code}")
def api_mfa_enroll_code(code: str) -> Response:
    payload = resolve_enroll_code(code)
    if not payload:
        return Response(content=json.dumps({"error": "invalid_or_expired"}), media_type="application/json", status_code=404)
    return Response(content=json.dumps(payload), media_type="application/json")


@router.post("/api/mfa/enroll")
def api_mfa_enroll(payload: Dict[str, Any]) -> Response:
    enroll_token = (payload.get("enroll_token") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    rp_id = (payload.get("rp_id") or "").strip()
    if not enroll_token or not email or not rp_id:
        return Response(content=json.dumps({"error": "missing_fields"}), media_type="application/json", status_code=400)

    try:
        token_data = decode_enroll_token(enroll_token)
    except (BadSignature, SignatureExpired):
        return Response(content=json.dumps({"error": "invalid_token"}), media_type="application/json", status_code=400)

    if token_data.get("email", "").lower() != email or token_data.get("rp_id") != rp_id:
        return Response(content=json.dumps({"error": "token_mismatch"}), media_type="application/json", status_code=400)

    pending_id = token_data.get("pending_id")
    with db_connect() as conn:
        pending = conn.execute("SELECT * FROM pending_totp WHERE id = ?", (pending_id,)).fetchone()
        if not pending or pending["expires_at"] < int(time.time()):
            return Response(content=json.dumps({"error": "pending_expired"}), media_type="application/json", status_code=400)

        user = conn.execute("SELECT * FROM users WHERE id = ?", (token_data.get("user_id"),)).fetchone()
        if not user:
            return Response(content=json.dumps({"error": "user_not_found"}), media_type="application/json", status_code=404)

        device_label = payload.get("device_label") or "ZT-Authenticator Device"
        platform = payload.get("platform") or "unknown"
        key_type = payload.get("key_type") or "p256"
        public_key = payload.get("public_key") or ""
        if not public_key:
            return Response(content=json.dumps({"error": "public_key_required"}), media_type="application/json", status_code=400)

        cur = conn.execute(
            "INSERT INTO devices (user_id, device_label, platform, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], device_label, platform, int(time.time())),
        )
        device_id = cur.lastrowid
        conn.execute(
            "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
            (device_id, rp_id, key_type, public_key, int(time.time())),
        )

    return Response(
        content=json.dumps({"user": {"id": str(user["id"])}, "device": {"id": str(device_id)}}),
        media_type="application/json",
    )


@router.get("/api/auth/enroll-code/{code}")
def api_auth_enroll_code(code: str) -> Response:
    return api_mfa_enroll_code(code)


@router.post("/api/auth/enroll")
def api_auth_enroll(payload: Dict[str, Any]) -> Response:
    return api_mfa_enroll(payload)


@router.post("/api/auth/totp/register")
def api_auth_totp_register(payload: Dict[str, Any]) -> Response:
    return api_mfa_totp_register(payload)


@router.get("/api/auth/login/pending")
def api_auth_login_pending(user_id: int) -> Response:
    with db_connect() as conn:
        challenge = conn.execute(
            """
            SELECT * FROM login_challenges
            WHERE user_id = ? AND status = 'pending' AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (user_id, int(time.time())),
        ).fetchone()
    if not challenge:
        return Response(content=json.dumps({"status": "none"}), media_type="application/json")
    expires_in = max(0, challenge["expires_at"] - int(time.time()))
    payload = {
        "status": "pending",
        "login_id": str(challenge["id"]),
        "nonce": challenge["nonce"],
        "rp_id": challenge["rp_id"],
        "device_id": str(challenge["device_id"]),
        "expires_in": expires_in,
    }
    return Response(content=json.dumps(payload), media_type="application/json")


@router.get("/api/auth/login/status")
def api_auth_login_status(login_id: int) -> Response:
    with db_connect() as conn:
        challenge = conn.execute(
            "SELECT * FROM login_challenges WHERE id = ?",
            (login_id,),
        ).fetchone()
    if not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "not_found"}), media_type="application/json")
    return Response(
        content=json.dumps({"status": challenge["status"], "reason": challenge["denied_reason"]}),
        media_type="application/json",
    )


@router.post("/api/auth/login/clear")
def api_auth_login_clear(payload: Dict[str, Any]) -> Response:
    user_id = payload.get("user_id")
    if not user_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_user_id"}), media_type="application/json", status_code=400)
    with db_connect() as conn:
        conn.execute(
            """
            UPDATE login_challenges
            SET status = ?, denied_reason = ?
            WHERE user_id = ? AND status = 'pending'
            """,
            ("denied", "cleared", user_id),
        )
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.post("/api/auth/login/approve")
def api_auth_login_approve(payload: Dict[str, Any]) -> Response:
    login_id_raw = payload.get("login_id")
    device_id_raw = payload.get("device_id")
    rp_id = (payload.get("rp_id") or "").strip()
    otp = (payload.get("otp") or "").strip()
    nonce = (payload.get("nonce") or "").strip()
    signature = (payload.get("signature") or "").strip()
    if not login_id_raw or not device_id_raw or not rp_id or not otp or not nonce or not signature:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_fields"}), media_type="application/json", status_code=400)
    try:
        login_id = int(login_id_raw)
        device_id = int(device_id_raw)
    except (TypeError, ValueError):
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_ids"}), media_type="application/json", status_code=400)

    with db_connect() as conn:
        challenge = conn.execute(
            "SELECT * FROM login_challenges WHERE id = ?",
            (login_id,),
        ).fetchone()
        if not challenge or challenge["status"] != "pending":
            return Response(content=json.dumps({"status": "denied", "reason": "not_pending"}), media_type="application/json")
        if challenge["device_id"] != device_id or challenge["rp_id"] != rp_id or challenge["nonce"] != nonce:
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "mismatch", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "mismatch"}), media_type="application/json")

        user = conn.execute("SELECT * FROM users WHERE id = ?", (challenge["user_id"],)).fetchone()
        if not user or not user["otp_secret"]:
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "totp_not_registered", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "totp_not_registered"}), media_type="application/json")

        if hash_otp(otp) != challenge["otp_hash"]:
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "otp_mismatch", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "otp_mismatch"}), media_type="application/json")

        totp = pyotp.TOTP(user["otp_secret"])
        if not totp.verify(otp, valid_window=1):
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "invalid_otp", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "invalid_otp"}), media_type="application/json")

        device_key = conn.execute(
            "SELECT * FROM device_keys WHERE device_id = ? AND rp_id = ? ORDER BY created_at DESC LIMIT 1",
            (device_id, rp_id),
        ).fetchone()
        if not device_key:
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "device_not_enrolled", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "device_not_enrolled"}), media_type="application/json")

        message = f"{nonce}|{device_id}|{rp_id}|{otp}".encode("utf-8")
        if device_key["key_type"] != "p256" or not verify_p256_signature(device_key["public_key"], message, signature):
            conn.execute("UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?", ("denied", "invalid_device_proof", login_id))
            return Response(content=json.dumps({"status": "denied", "reason": "invalid_device_proof"}), media_type="application/json")

        conn.execute("UPDATE login_challenges SET status = ?, approved_at = ? WHERE id = ?", ("ok", int(time.time()), login_id))

    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.post("/api/auth/login/deny")
def api_auth_login_deny(payload: Dict[str, Any]) -> Response:
    login_id = payload.get("login_id")
    reason = (payload.get("reason") or "user_denied").strip()
    if not login_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_login_id"}), media_type="application/json", status_code=400)
    with db_connect() as conn:
        conn.execute(
            "UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?",
            ("denied", reason, login_id),
        )
    return Response(content=json.dumps({"status": "denied", "reason": reason}), media_type="application/json")


@router.post("/api/mfa/totp/register")
def api_mfa_totp_register(payload: Dict[str, Any]) -> Response:
    user_id = payload.get("user_id")
    rp_id = (payload.get("rp_id") or "").strip()
    account_name = (payload.get("account_name") or "").strip()
    issuer = (payload.get("issuer") or "PoIA Bank").strip()
    if not user_id or not rp_id or not account_name:
        return Response(content=json.dumps({"detail": "missing_fields"}), media_type="application/json", status_code=400)
    if rp_id != APP_RP_ID:
        return Response(content=json.dumps({"detail": "rp_mismatch"}), media_type="application/json", status_code=400)

    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return Response(content=json.dumps({"detail": "user_not_found"}), media_type="application/json", status_code=404)

        pending = conn.execute("SELECT * FROM pending_totp WHERE user_id = ?", (user_id,)).fetchone()
        if pending and pending["expires_at"] < int(time.time()):
            conn.execute("DELETE FROM pending_totp WHERE id = ?", (pending["id"],))
            pending = None

        if not pending:
            secret = pyotp.random_base32()
            expires_at = int(time.time()) + (MFA_ENROLL_TTL_MINUTES * 60)
            cur = conn.execute(
                "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, secret, user["email"], expires_at),
            )
            pending_id = cur.lastrowid
            pending = conn.execute("SELECT * FROM pending_totp WHERE id = ?", (pending_id,)).fetchone()

    otpauth_uri = pyotp.TOTP(pending["secret"]).provisioning_uri(name=account_name, issuer_name=issuer)
    recovery_codes = [secrets.token_hex(4) for _ in range(8)]
    return Response(
        content=json.dumps({"otpauth_uri": otpauth_uri, "recovery_codes": recovery_codes}),
        media_type="application/json",
    )


@router.get("/mfa/verify", response_class=HTMLResponse)
def mfa_verify_page(request: Request) -> HTMLResponse:
    if not request.session.get("pre_mfa_user_id"):
        if get_current_user(request):
            user = get_current_user(request)
            if user and user["is_admin"]:
                return RedirectResponse(url="/admin/dashboard", status_code=302)
            return RedirectResponse(url="/dashboard", status_code=302)
        return RedirectResponse(url="/login", status_code=302)
    return render(request, "verify_totp.html", {"error": ""})


@router.post("/mfa/verify", response_class=HTMLResponse)
def mfa_verify_submit(request: Request, otp: str = Form("")) -> HTMLResponse:
    user_id = request.session.get("pre_mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    if not otp:
        return render(request, "verify_totp.html", {"error": "OTP is required."})

    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        pending = conn.execute("SELECT * FROM pending_totp WHERE user_id = ?", (user_id,)).fetchone()

    secret = pending["secret"] if pending else (user["otp_secret"] if user else None)
    if not secret:
        return RedirectResponse(url="/mfa/setup?reason=setup", status_code=302)

    start_time = time.time()
    totp = pyotp.TOTP(secret)
    ok = bool(totp.verify(otp, valid_window=1))
    duration_ms = int((time.time() - start_time) * 1000)
    if not ok:
        log_mfa_event(user_id, "denied", "invalid_otp", duration_ms)
        return render(request, "verify_totp.html", {"error": "Invalid or expired OTP."})

    if pending:
        with db_connect() as conn:
            conn.execute(
                "UPDATE users SET otp_secret = ?, otp_email_label = ?, otp_rp_id = ? WHERE id = ?",
                (pending["secret"], pending["email"], APP_RP_ID, user_id),
            )
            conn.execute("DELETE FROM pending_totp WHERE id = ?", (pending["id"],))

    with db_connect() as conn:
        device = conn.execute(
            "SELECT id FROM devices WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if not device:
            return RedirectResponse(url="/mfa/setup?reason=setup", status_code=302)
        nonce = secrets.token_urlsafe(24)
        expires_at = int(time.time()) + 120
        conn.execute(
            """
            INSERT INTO login_challenges (user_id, device_id, rp_id, nonce, otp_hash, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, device["id"], APP_RP_ID, nonce, hash_otp(otp), "pending", int(time.time()), expires_at),
        )
        challenge_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    request.session["totp_verified"] = True
    request.session["pending_login_id"] = challenge_id
    log_mfa_event(user_id, "ok", "totp_verified", duration_ms)
    return RedirectResponse(url="/mfa/device-pending", status_code=303)


@router.get("/mfa/device-pending", response_class=HTMLResponse)
def mfa_device_pending(request: Request) -> HTMLResponse:
    if not request.session.get("totp_verified"):
        return RedirectResponse(url="/mfa/verify", status_code=302)
    return render(request, "device_pending.html", {})


@router.post("/mfa/cancel")
def mfa_cancel(request: Request) -> RedirectResponse:
    user_id = request.session.get("pre_mfa_user_id")
    login_id = request.session.get("pending_login_id")
    if user_id and login_id:
        with db_connect() as conn:
            conn.execute(
                "UPDATE login_challenges SET status = ?, denied_reason = ? WHERE id = ?",
                ("denied", "user_cancelled", login_id),
            )
    request.session.pop("totp_verified", None)
    request.session.pop("pending_login_id", None)
    return RedirectResponse(url="/login", status_code=303)


@router.get("/api/mfa/device-status")
def api_mfa_device_status(request: Request) -> Response:
    user_id = request.session.get("pre_mfa_user_id")
    login_id = request.session.get("pending_login_id")
    if not user_id or not login_id:
        return Response(content=json.dumps({"status": "denied", "reason": "no_session"}), media_type="application/json")

    with db_connect() as conn:
        challenge = conn.execute(
            "SELECT * FROM login_challenges WHERE id = ? AND user_id = ?",
            (login_id, user_id),
        ).fetchone()

    if not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "not_found"}), media_type="application/json")

    if challenge["status"] == "ok":
        request.session["user_id"] = user_id
        request.session.pop("pre_mfa_user_id", None)
        request.session.pop("pre_mfa_email", None)
        request.session.pop("totp_verified", None)
        request.session.pop("pending_login_id", None)
        with db_connect() as conn:
            conn.execute("UPDATE users SET mfa_enrolled = 1 WHERE id = ?", (user_id,))
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        log_audit(user_id, "login", "User logged in with TOTP + device approval")
        redirect_url = "/admin/dashboard" if user and user["is_admin"] else "/dashboard"
        return Response(content=json.dumps({"status": "ok", "redirect_url": redirect_url}), media_type="application/json")

    if challenge["status"] == "denied":
        return Response(
            content=json.dumps({"status": "denied", "reason": challenge["denied_reason"]}),
            media_type="application/json",
        )

    return Response(content=json.dumps({"status": "pending"}), media_type="application/json")
