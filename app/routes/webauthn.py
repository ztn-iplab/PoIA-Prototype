import base64
import json
import secrets
import time
from typing import Any, Dict

from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import get_current_user, log_audit, render, require_login
from ..db import db_connect
from ..reset import validate_reset_token
from ..webauthn_utils import (
    attested_from_row,
    b64encode,
    get_webauthn_server,
    load_credentials,
    webauthn_jsonify,
    webauthn_state_store,
)

router = APIRouter()
server = get_webauthn_server()


@router.get("/webauthn/setup", response_class=HTMLResponse)
def webauthn_setup(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    return render(request, "webauthn_setup.html", {})


@router.post("/webauthn/register-begin")
def webauthn_register_begin(request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)

    with db_connect() as conn:
        rows = conn.execute(
            "SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?",
            (user["id"],),
        ).fetchall()
    credentials = []
    for row in rows:
        if not row["credential_id"]:
            continue
        transports = row["transports"].split(",") if row["transports"] else []
        entry = {
            "id": websafe_decode(row["credential_id"].encode("ascii")),
            "type": "public-key",
        }
        if transports:
            entry["transports"] = transports
        credentials.append(entry)
    display_name = user["email"] or f"User {user['id']}"
    user_name = user["email"] or display_name
    user_id_raw = user["id"] if user and "id" in user.keys() else None
    if user_id_raw is None:
        return Response(
            content=json.dumps({"error": "register_begin_failed", "detail": "missing_user_id"}),
            media_type="application/json",
            status_code=400,
        )
    user_id = base64.urlsafe_b64encode(str(user_id_raw).encode("utf-8")).decode("ascii").rstrip("=")
    try:
        user_entity = {
            "id": user_id,
            "name": user_name,
            "displayName": display_name,
        }
        if credentials:
            registration_data, state = server.register_begin(user_entity, credentials)
        else:
            registration_data, state = server.register_begin(user_entity)
        register_token = secrets.token_urlsafe(32)
        webauthn_state_store.set(register_token, state)
        request.session["webauthn_register_token"] = register_token
        public_key = webauthn_jsonify(registration_data["publicKey"])
        return Response(content=json.dumps({"public_key": public_key}), media_type="application/json")
    except Exception as exc:
        import traceback

        detail = (
            f"{type(exc).__name__}: {exc} | "
            f"user_name={user_name!r} display_name={display_name!r} "
            f"cred_count={len(credentials)}\n{traceback.format_exc()}"
        )
        return Response(
            content=json.dumps({"error": "register_begin_failed", "detail": detail}),
            media_type="application/json",
            status_code=400,
        )


@router.post("/webauthn/register-complete")
def webauthn_register_complete(payload: Dict[str, Any], request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)

    register_token = request.session.get("webauthn_register_token")
    if not register_token:
        return Response(content=json.dumps({"error": "no_registration"}), media_type="application/json", status_code=400)
    state = webauthn_state_store.get(register_token)
    if not state:
        return Response(content=json.dumps({"error": "registration_expired"}), media_type="application/json", status_code=400)

    if payload.get("id") != payload.get("rawId"):
        return Response(content=json.dumps({"error": "id_mismatch"}), media_type="application/json", status_code=400)

    response = {
        "id": payload["id"],
        "rawId": payload["rawId"],
        "type": payload.get("type", "public-key"),
        "response": {
            "attestationObject": payload["response"]["attestationObject"],
            "clientDataJSON": payload["response"]["clientDataJSON"],
        },
    }
    try:
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        return Response(
            content=json.dumps({"error": "register_complete_failed", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )
    cred_data = auth_data.credential_data
    public_key_bytes = cbor.encode(cred_data.public_key)

    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                b64encode(cred_data.credential_id),
                base64.b64encode(public_key_bytes).decode("ascii"),
                0,
                ",".join(payload.get("transports", [])),
                int(time.time()),
            ),
        )
        conn.execute("UPDATE users SET mfa_enrolled = 1 WHERE id = ?", (user["id"],))

    webauthn_state_store.clear(register_token)
    request.session.pop("webauthn_register_token", None)
    log_audit(user["id"], "webauthn_register", "Passkey registered")
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.get("/mfa/passkey", response_class=HTMLResponse)
def mfa_passkey_page(request: Request) -> HTMLResponse:
    user_id = request.session.get("pre_mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    with db_connect() as conn:
        credential = conn.execute(
            "SELECT id FROM webauthn_credentials WHERE user_id = ? LIMIT 1",
            (user_id,),
        ).fetchone()
    if not credential:
        return render(
            request,
            "webauthn_verify.html",
            {"no_passkey": True},
        )
    return render(request, "webauthn_verify.html", {"no_passkey": False})


@router.post("/webauthn/assertion-begin")
def webauthn_assertion_begin(request: Request) -> Response:
    user_id = request.session.get("pre_mfa_user_id") or request.session.get("user_id")
    if not user_id:
        return Response(content=json.dumps({"error": "no_session"}), media_type="application/json", status_code=401)

    credentials, _descriptors = load_credentials(user_id)
    if not credentials:
        return Response(content=json.dumps({"error": "no_credentials"}), media_type="application/json", status_code=404)

    try:
        assertion_data, state = server.authenticate_begin(credentials)
        assertion_token = secrets.token_urlsafe(32)
        webauthn_state_store.set(assertion_token, state)
        request.session["webauthn_assertion_token"] = assertion_token
        request.session["webauthn_assertion_user_id"] = user_id
        options = assertion_data.public_key
        public_key_dict = {
            "challenge": websafe_encode(options.challenge),
            "rpId": options.rp_id,
            "allowCredentials": [
                {
                    "type": c.type.value,
                    "id": websafe_encode(c.id),
                    "transports": [t.value for t in c.transports] if c.transports else [],
                }
                for c in options.allow_credentials or []
            ],
            "userVerification": options.user_verification,
            "timeout": options.timeout,
        }
        return Response(content=json.dumps({"public_key": public_key_dict}), media_type="application/json")
    except Exception as exc:
        return Response(
            content=json.dumps({"error": "assertion_begin_failed", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )


@router.post("/webauthn/assertion-complete")
def webauthn_assertion_complete(payload: Dict[str, Any], request: Request) -> Response:
    assertion_token = request.session.get("webauthn_assertion_token")
    user_id = request.session.get("webauthn_assertion_user_id")
    if not assertion_token or not user_id:
        return Response(content=json.dumps({"error": "no_assertion"}), media_type="application/json", status_code=400)
    state = webauthn_state_store.get(assertion_token)
    if not state:
        return Response(content=json.dumps({"error": "assertion_expired"}), media_type="application/json", status_code=400)

    credential_id = websafe_decode(payload["credentialId"])
    with db_connect() as conn:
        credential = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?",
            (user_id, b64encode(credential_id)),
        ).fetchone()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not credential or not user:
        return Response(content=json.dumps({"error": "credential_not_found"}), media_type="application/json", status_code=404)

    assertion = {
        "id": payload["credentialId"],
        "rawId": payload["credentialId"],
        "type": "public-key",
        "response": {
            "authenticatorData": payload["authenticatorData"],
            "clientDataJSON": payload["clientDataJSON"],
            "signature": payload["signature"],
            "userHandle": payload.get("userHandle"),
        },
    }

    public_key_source = attested_from_row(credential)
    try:
        server.authenticate_complete(state, [public_key_source], assertion)
    except Exception as exc:
        return Response(
            content=json.dumps({"error": "assertion_complete_failed", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )
    with db_connect() as conn:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = sign_count + 1 WHERE id = ?",
            (credential["id"],),
        )
        conn.execute("UPDATE users SET mfa_enrolled = 1 WHERE id = ?", (user_id,))

    request.session["user_id"] = user_id
    request.session.pop("pre_mfa_user_id", None)
    request.session.pop("pre_mfa_email", None)
    webauthn_state_store.clear(assertion_token)
    request.session.pop("webauthn_assertion_token", None)
    request.session.pop("webauthn_assertion_user_id", None)
    log_audit(user_id, "login", "User logged in with passkey")
    redirect_url = "/admin/dashboard" if user and user["is_admin"] else "/dashboard"
    return Response(content=json.dumps({"status": "ok", "redirect_url": redirect_url}), media_type="application/json")


@router.post("/webauthn/reset-password-begin")
def webauthn_reset_password_begin(payload: Dict[str, Any], request: Request) -> Response:
    token = payload.get("token", "")
    user = validate_reset_token(token, "password")
    if not user:
        return Response(content=json.dumps({"error": "invalid_token"}), media_type="application/json", status_code=400)

    credentials, _descriptors = load_credentials(user["id"])
    if not credentials:
        return Response(content=json.dumps({"error": "no_credentials"}), media_type="application/json", status_code=404)

    assertion_data, state = server.authenticate_begin(credentials)
    reset_token = secrets.token_urlsafe(32)
    webauthn_state_store.set(reset_token, state)
    request.session["reset_webauthn_token"] = reset_token
    request.session["reset_webauthn_user_id"] = user["id"]
    request.session["reset_webauthn_purpose"] = "password"
    options = assertion_data.public_key
    public_key_dict = {
        "challenge": websafe_encode(options.challenge),
        "rpId": options.rp_id,
        "allowCredentials": [
            {"type": c.type.value, "id": websafe_encode(c.id)} for c in options.allow_credentials or []
        ],
        "userVerification": options.user_verification,
        "timeout": options.timeout,
    }
    return Response(content=json.dumps({"public_key": public_key_dict}), media_type="application/json")


@router.post("/webauthn/reset-totp-begin")
def webauthn_reset_totp_begin(payload: Dict[str, Any], request: Request) -> Response:
    token = payload.get("token", "")
    user = validate_reset_token(token, "totp")
    if not user:
        return Response(content=json.dumps({"error": "invalid_token"}), media_type="application/json", status_code=400)

    credentials, _descriptors = load_credentials(user["id"])
    if not credentials:
        return Response(content=json.dumps({"error": "no_credentials"}), media_type="application/json", status_code=404)

    assertion_data, state = server.authenticate_begin(credentials)
    reset_token = secrets.token_urlsafe(32)
    webauthn_state_store.set(reset_token, state)
    request.session["reset_webauthn_token"] = reset_token
    request.session["reset_webauthn_user_id"] = user["id"]
    request.session["reset_webauthn_purpose"] = "totp"
    options = assertion_data.public_key
    public_key_dict = {
        "challenge": websafe_encode(options.challenge),
        "rpId": options.rp_id,
        "allowCredentials": [
            {"type": c.type.value, "id": websafe_encode(c.id)} for c in options.allow_credentials or []
        ],
        "userVerification": options.user_verification,
        "timeout": options.timeout,
    }
    return Response(content=json.dumps({"public_key": public_key_dict}), media_type="application/json")


@router.post("/webauthn/reset-complete")
def webauthn_reset_complete(payload: Dict[str, Any], request: Request) -> Response:
    reset_token = request.session.get("reset_webauthn_token")
    user_id = request.session.get("reset_webauthn_user_id")
    purpose = request.session.get("reset_webauthn_purpose")
    if not reset_token or not user_id or not purpose:
        return Response(content=json.dumps({"error": "no_reset_state"}), media_type="application/json", status_code=400)
    state = webauthn_state_store.get(reset_token)
    if not state:
        return Response(content=json.dumps({"error": "reset_expired"}), media_type="application/json", status_code=400)

    credential_id = websafe_decode(payload["credentialId"])
    with db_connect() as conn:
        credential = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?",
            (user_id, b64encode(credential_id)),
        ).fetchone()
    if not credential:
        return Response(content=json.dumps({"error": "credential_not_found"}), media_type="application/json", status_code=404)

    assertion = {
        "id": payload["credentialId"],
        "rawId": payload["credentialId"],
        "type": "public-key",
        "response": {
            "authenticatorData": payload["authenticatorData"],
            "clientDataJSON": payload["clientDataJSON"],
            "signature": payload["signature"],
            "userHandle": payload.get("userHandle"),
        },
    }

    public_key_source = attested_from_row(credential)
    server.authenticate_complete(state, [public_key_source], assertion)
    with db_connect() as conn:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = sign_count + 1 WHERE id = ?",
            (credential["id"],),
        )
    if purpose == "password":
        request.session["reset_password_webauthn_ok"] = True
    if purpose == "totp":
        request.session["reset_totp_webauthn_ok"] = True
    webauthn_state_store.clear(reset_token)
    request.session.pop("reset_webauthn_token", None)
    request.session.pop("reset_webauthn_user_id", None)
    request.session.pop("reset_webauthn_purpose", None)
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")
