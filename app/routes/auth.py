import time

import pyotp
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..core import get_current_user, log_audit, render, require_login
from ..db import db_connect
from ..mfa_utils import device_enrolled, resolve_public_base_url
from ..mfa_utils import totp_needs_reset
from ..webauthn_utils import user_has_webauthn
from ..settings import APP_RP_ID
from ..reset import clear_reset_token, issue_reset_token, validate_reset_token
from ..security import hash_password, password_is_strong, send_email, verify_password

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if user:
        if user["is_admin"]:
            return RedirectResponse(url="/admin/dashboard", status_code=302)
        return RedirectResponse(url="/dashboard", status_code=302)
    return render(request, "home.html")


@router.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request) -> HTMLResponse:
    return render(request, "signup.html", {"error": ""})


@router.post("/signup", response_class=HTMLResponse)
def signup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    if not password_is_strong(password):
        return render(
            request,
            "signup.html",
            {"error": "Password must be 12+ chars with upper, lower, number, and symbol."},
        )
    with db_connect() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return render(request, "signup.html", {"error": "Email already registered."})

        conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (email, hash_password(password), 0, int(time.time())),
        )
        user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
        conn.execute(
            "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
            (user_id, "checking", 2500.0, int(time.time())),
        )
        conn.execute(
            "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
            (user_id, "savings", 5000.0, int(time.time())),
        )

    log_audit(user_id, "signup", f"User {email} registered")
    request.session["pre_mfa_user_id"] = user_id
    request.session["pre_mfa_email"] = email
    request.session.pop("user_id", None)
    return RedirectResponse(url="/mfa/setup", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    message = request.query_params.get("message", "")
    if not message:
        message = request.session.pop("flash_message", "")
    return render(request, "login.html", {"error": "", "message": message, "flash_message": message})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return render(request, "login.html", {"error": "Invalid credentials."})

    request.session["pre_mfa_user_id"] = user["id"]
    request.session["pre_mfa_email"] = user["email"]
    has_device = device_enrolled(user["id"])
    reset_required = totp_needs_reset(user, has_device)
    can_use_totp = bool(user["otp_secret"]) and not reset_required and has_device
    has_webauthn = user_has_webauthn(user["id"])
    reset_reason = request.session.pop("mfa_reset_reason", "")
    if reset_reason:
        return RedirectResponse(url=f"/mfa/setup?reason={reset_reason}", status_code=303)
    if not can_use_totp and not has_webauthn:
        reason = "rp_changed" if user["otp_rp_id"] and user["otp_rp_id"] != APP_RP_ID else "required"
        return RedirectResponse(url=f"/mfa/setup?reason={reason}", status_code=303)
    if (can_use_totp or reset_required) and has_webauthn:
        return RedirectResponse(url="/mfa/choose", status_code=303)
    if has_webauthn:
        return RedirectResponse(url="/mfa/passkey", status_code=303)
    if reset_required:
        return RedirectResponse(url="/mfa/setup", status_code=303)
    return RedirectResponse(url="/mfa/verify", status_code=303)


@router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    user = get_current_user(request)
    if user:
        log_audit(user["id"], "logout", "User logged out")
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request) -> HTMLResponse:
    return render(request, "forgot_password.html", {"message": "", "reset_link": ""})


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(request: Request, email: str = Form(...)) -> HTMLResponse:
    reset_link = ""
    email_sent = False
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = issue_reset_token(user["id"], "password")
            base_url = resolve_public_base_url(request)
            reset_link = f"{base_url}/reset-password?token={token}"
            email_body = "\n".join(
                [
                    "We received a password reset request for your PoIA Bank account.",
                    "",
                    f"Reset link (valid for 15 minutes): {reset_link}",
                    "",
                    "If you did not request this, you can ignore this message.",
                ]
            )
            email_sent = send_email(user["email"], "PoIA Bank Password Reset", email_body)
            log_audit(user["id"], "password_reset_request", "Password reset link issued")
    if email_sent:
        message = "If the account exists, a reset email has been sent."
    else:
        message = "If the account exists, a reset link has been generated for this demo."
    return render(request, "forgot_password.html", {"message": message, "reset_link": reset_link})


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_form(request: Request) -> HTMLResponse:
    token = request.query_params.get("token", "")
    return render(request, "reset_password.html", {"error": "", "token": token})


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    request: Request,
    token: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    otp: str = Form(""),
) -> HTMLResponse:
    if not token:
        return render(request, "reset_password.html", {"error": "Reset token is required.", "token": ""})
    if not otp and not request.session.get("reset_password_webauthn_ok"):
        return render(request, "reset_password.html", {"error": "TOTP code is required.", "token": token})
    if not password or not confirm_password:
        return render(request, "reset_password.html", {"error": "Both password fields are required.", "token": token})
    if password != confirm_password:
        return render(request, "reset_password.html", {"error": "Passwords do not match.", "token": token})
    if not password_is_strong(password):
        return render(
            request,
            "reset_password.html",
            {"error": "Password must be 12+ chars with upper, lower, number, and symbol.", "token": token},
        )

    user = validate_reset_token(token, "password")
    if not user:
        return render(request, "reset_password.html", {"error": "Reset token is invalid or expired.", "token": ""})
    if not request.session.get("reset_password_webauthn_ok"):
        if not user["otp_secret"]:
            return render(request, "reset_password.html", {"error": "TOTP is not configured for this account.", "token": ""})
        totp = pyotp.TOTP(user["otp_secret"])
        if not totp.verify(otp.strip(), valid_window=1):
            return render(request, "reset_password.html", {"error": "Invalid TOTP code.", "token": token})

    with db_connect() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user["id"]))
    clear_reset_token(user["id"])
    request.session.pop("reset_password_webauthn_ok", None)
    log_audit(user["id"], "password_reset", "Password reset completed")
    request.session["flash_message"] = "Password reset complete. Please sign in with your new password."
    return RedirectResponse(url="/login", status_code=303)


@router.get("/request-totp-reset", response_class=HTMLResponse)
def request_totp_reset_form(request: Request) -> HTMLResponse:
    return render(request, "request_totp_reset.html", {"message": "", "reset_link": ""})


@router.post("/request-totp-reset", response_class=HTMLResponse)
def request_totp_reset_submit(request: Request, email: str = Form(...)) -> HTMLResponse:
    reset_link = ""
    email_sent = False
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = issue_reset_token(user["id"], "totp")
            base_url = resolve_public_base_url(request)
            reset_link = f"{base_url}/reset-totp?token={token}"
            email_body = "\n".join(
                [
                    "We received a TOTP reset request for your PoIA Bank account.",
                    "",
                    f"Reset link (valid for 15 minutes): {reset_link}",
                    "",
                    "If you did not request this, you can ignore this message.",
                ]
            )
            email_sent = send_email(user["email"], "PoIA Bank TOTP Reset", email_body)
            log_audit(user["id"], "totp_reset_request", "TOTP reset link issued")
    if email_sent:
        message = "If the account exists, a reset email has been sent."
    else:
        message = "If the account exists, a reset link has been generated for this demo."
    return render(request, "request_totp_reset.html", {"message": message, "reset_link": reset_link})


@router.get("/reset-totp", response_class=HTMLResponse)
def reset_totp_form(request: Request) -> HTMLResponse:
    token = request.query_params.get("token", "")
    return render(request, "reset_totp.html", {"error": "", "token": token})


@router.post("/reset-totp", response_class=HTMLResponse)
def reset_totp_submit(request: Request, token: str = Form(""), password: str = Form("")) -> HTMLResponse:
    if not token:
        return render(request, "reset_totp.html", {"error": "Reset token is required.", "token": ""})

    user = validate_reset_token(token, "totp")
    if not user:
        return render(request, "reset_totp.html", {"error": "Reset token is invalid or expired.", "token": ""})
    if not password and not request.session.get("reset_totp_webauthn_ok"):
        return render(request, "reset_totp.html", {"error": "Password is required.", "token": token})
    if password and not verify_password(password, user["password_hash"]):
        return render(request, "reset_totp.html", {"error": "Password is incorrect.", "token": token})

    with db_connect() as conn:
        device_ids = [row["id"] for row in conn.execute("SELECT id FROM devices WHERE user_id = ?", (user["id"],)).fetchall()]
        if device_ids:
            placeholders = ",".join("?" for _ in device_ids)
            conn.execute(f"DELETE FROM device_keys WHERE device_id IN ({placeholders})", device_ids)
        conn.execute("DELETE FROM devices WHERE user_id = ?", (user["id"],))
        conn.execute("DELETE FROM pending_totp WHERE user_id = ?", (user["id"],))
        conn.execute(
            "UPDATE users SET otp_secret = NULL, otp_email_label = NULL, otp_rp_id = NULL, mfa_enrolled = 0 WHERE id = ?",
            (user["id"],),
        )
    clear_reset_token(user["id"])
    request.session.pop("reset_totp_webauthn_ok", None)
    log_audit(user["id"], "totp_reset", "TOTP reset completed")
    request.session["flash_message"] = "TOTP reset. Please sign in to re-enroll your device."
    request.session["mfa_reset_reason"] = "reset"
    return RedirectResponse(url="/login", status_code=303)


@router.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    with db_connect() as conn:
        account_count = conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE user_id = ?",
            (user["id"],),
        ).fetchone()[0]
        device_count = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE user_id = ?",
            (user["id"],),
        ).fetchone()[0]
        last_login = conn.execute(
            """
            SELECT created_at
            FROM audit_logs
            WHERE user_id = ? AND action = 'login'
            ORDER BY created_at DESC LIMIT 1
            """,
            (user["id"],),
        ).fetchone()
        last_login_at = last_login["created_at"] if last_login else None

    return render(
        request,
        "profile.html",
        {
            "account_count": account_count,
            "device_count": device_count,
            "last_login_at": last_login_at,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    return render(request, "settings.html", {"error": "", "success": ""})


@router.post("/settings/password", response_class=HTMLResponse)
def settings_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    if not current_password or not new_password or not confirm_password:
        return render(request, "settings.html", {"error": "All fields are required.", "success": ""})
    if new_password != confirm_password:
        return render(request, "settings.html", {"error": "Passwords do not match.", "success": ""})
    if not password_is_strong(new_password):
        return render(
            request,
            "settings.html",
            {"error": "Password must be 12+ chars with upper, lower, number, and symbol.", "success": ""},
        )
    if not verify_password(current_password, user["password_hash"]):
        return render(request, "settings.html", {"error": "Current password is incorrect.", "success": ""})

    with db_connect() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
    log_audit(user["id"], "password_change", "Password changed from settings")
    return render(request, "settings.html", {"error": "", "success": "Password updated."})


@router.post("/settings/poia", response_class=HTMLResponse)
def settings_poia(request: Request, poia_zt_enabled: str = Form("")) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    enabled = 1 if poia_zt_enabled == "on" else 0
    with db_connect() as conn:
        conn.execute("UPDATE users SET poia_zt_enabled = ? WHERE id = ?", (enabled, user["id"]))
    request.session["flash_message"] = "PoIA approval preference updated."
    return RedirectResponse(url="/settings", status_code=303)


@router.post("/settings/poia/", response_class=HTMLResponse)
def settings_poia_trailing(request: Request, poia_zt_enabled: str = Form("")) -> HTMLResponse:
    return settings_poia(request, poia_zt_enabled)


@router.get("/settings/poia/")
def settings_poia_trailing_get() -> RedirectResponse:
    return RedirectResponse(url="/settings", status_code=302)


@router.get("/reset-passkey", response_class=HTMLResponse)
def reset_passkey_form(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not user and not request.session.get("pre_mfa_user_id"):
        return RedirectResponse(url="/login", status_code=302)
    return render(request, "reset_passkey.html", {"error": "", "success": ""})


@router.post("/reset-passkey", response_class=HTMLResponse)
def reset_passkey_submit(
    request: Request,
    password: str = Form(""),
    otp: str = Form(""),
) -> HTMLResponse:
    user_id = request.session.get("user_id") or request.session.get("pre_mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return render(request, "reset_passkey.html", {"error": "User not found.", "success": ""})

    if not password and not otp:
        return render(request, "reset_passkey.html", {"error": "Provide password or TOTP.", "success": ""})

    if password and not verify_password(password, user["password_hash"]):
        return render(request, "reset_passkey.html", {"error": "Password is incorrect.", "success": ""})

    if otp:
        if not user["otp_secret"]:
            return render(request, "reset_passkey.html", {"error": "TOTP is not configured.", "success": ""})
        totp = pyotp.TOTP(user["otp_secret"])
        if not totp.verify(otp.strip(), valid_window=1):
            return render(request, "reset_passkey.html", {"error": "Invalid TOTP code.", "success": ""})

    with db_connect() as conn:
        conn.execute("DELETE FROM webauthn_credentials WHERE user_id = ?", (user_id,))
    log_audit(user_id, "webauthn_reset", "Passkey reset using password or TOTP")

    request.session.pop("webauthn_assertion_token", None)
    request.session.pop("webauthn_assertion_user_id", None)

    should_force_login = not request.session.get("user_id")
    request.session.pop("pre_mfa_user_id", None)
    request.session.pop("pre_mfa_email", None)
    if should_force_login:
        request.session["flash_message"] = "Passkey reset. Please sign in again."
        return RedirectResponse(url="/login", status_code=303)
    return render(
        request,
        "reset_passkey.html",
        {"error": "", "success": "Passkey reset. You can register a new one from Settings."},
    )
