import base64
import hashlib
import json
import secrets
import time
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import (
    build_proof_payload,
    create_poia_intent,
    get_current_user,
    intent_hash,
    log_audit,
    poia_store,
    render,
    require_login,
)
from ..poia_metrics import log_poia_event
from ..model import ProofRecord
from ..db import db_connect
from ..routes.banking import (
    execute_beneficiary_add,
    execute_cash,
    execute_statements_export,
    execute_transfer,
)
from ..webauthn_utils import get_webauthn_server, load_credentials, webauthn_state_store
from ..settings import POIA_TEST_MODE, INTENT_TTL_SECONDS
from fido2.utils import websafe_decode, websafe_encode

router = APIRouter()
server = get_webauthn_server()


@router.get("/poia/approve/{intent_id}", response_class=HTMLResponse)
def poia_approve(request: Request, intent_id: str) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge_record:
        return render(request, "result.html", {"status": "Rejected", "message": "Intent expired or invalid."})

    return render(
        request,
        "approve.html",
        {
            "intent_id": intent_id,
            "intent": intent_record.intent_body,
            "nonce": challenge_record.nonce,
            "expires_at": int(challenge_record.expires_at),
        },
    )


@router.get("/poia/intent/{intent_id}")
def poia_intent(intent_id: str, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)
    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge_record:
        return Response(content=json.dumps({"error": "intent_invalid"}), media_type="application/json", status_code=404)
    if int(time.time()) > int(challenge_record.expires_at):
        log_poia_event(
            event="passkey_complete",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="expired",
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
            method="webauthn",
        )
        return Response(content=json.dumps({"error": "poia_expired"}), media_type="application/json", status_code=400)
    proof = poia_store.proofs.get(intent_id)
    if proof and proof.status != "pending":
        return Response(content=json.dumps({"error": "poia_replay"}), media_type="application/json", status_code=409)
    if intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return Response(content=json.dumps({"error": "intent_owner_mismatch"}), media_type="application/json", status_code=403)
    payload = {
        "intent": intent_record.intent_body,
        "nonce": challenge_record.nonce,
        "expires_at": int(challenge_record.expires_at),
        "intent_id": intent_id,
    }
    return Response(content=json.dumps(payload), media_type="application/json")


@router.post("/poia/assertion-begin")
def poia_assertion_begin(payload: dict, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)

    intent_id = payload.get("intent_id")
    if not intent_id:
        return Response(content=json.dumps({"error": "missing_intent"}), media_type="application/json", status_code=400)

    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge_record:
        return Response(content=json.dumps({"error": "intent_invalid"}), media_type="application/json", status_code=404)

    if intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return Response(content=json.dumps({"error": "intent_owner_mismatch"}), media_type="application/json", status_code=403)

    if int(time.time()) > int(challenge_record.expires_at):
        log_poia_event(
            event="passkey_begin",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="expired",
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
            method="webauthn",
        )
        return Response(content=json.dumps({"error": "poia_expired"}), media_type="application/json", status_code=400)

    credentials, _descriptors = load_credentials(user["id"])
    if not credentials:
        return Response(content=json.dumps({"error": "no_passkey"}), media_type="application/json", status_code=404)

    proof_payload = build_proof_payload(intent_record.intent_body, challenge_record.nonce, challenge_record.expires_at)
    challenge = hashlib.sha256(proof_payload).digest()
    try:
        assertion_data, state = server.authenticate_begin(credentials, challenge=challenge)
    except TypeError:
        assertion_data, state = server.authenticate_begin(credentials)
        try:
            assertion_data.public_key.challenge = challenge
        except Exception:
            pass
        try:
            state["challenge"] = challenge
        except Exception:
            pass
    token = secrets.token_urlsafe(32)
    webauthn_state_store.set(token, state)
    request.session["poia_assertion_token"] = token
    request.session["poia_intent_id"] = intent_id
    log_poia_event(
        event="passkey_begin",
        intent_id=intent_id,
        user_id=user["id"],
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=intent_record.intent_body.get("action"),
        status="ok",
        created_at=intent_record.created_at,
        expires_at=challenge_record.expires_at,
        method="webauthn",
    )

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


@router.post("/poia/assertion-complete")
def poia_assertion_complete(payload: dict, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"error": "unauthorized"}), media_type="application/json", status_code=401)

    intent_id = request.session.get("poia_intent_id")
    token = request.session.get("poia_assertion_token")
    if not intent_id or not token:
        return Response(content=json.dumps({"error": "no_poia_session"}), media_type="application/json", status_code=400)

    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge_record:
        return Response(content=json.dumps({"error": "intent_invalid"}), media_type="application/json", status_code=404)

    state = webauthn_state_store.get(token)
    if not state:
        return Response(content=json.dumps({"error": "poia_expired"}), media_type="application/json", status_code=400)

    credential_id = websafe_decode(payload["credentialId"])
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
    credentials, _descriptors = load_credentials(user["id"])
    try:
        server.authenticate_complete(state, credentials, assertion)
    except Exception as exc:
        log_poia_event(
            event="passkey_complete",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="verify_failed",
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
            method="webauthn",
            payload={"detail": str(exc)},
        )
        return Response(
            content=json.dumps({"error": "poia_verify_failed", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )

    latency_ms = int((time.time() - intent_record.created_at) * 1000)
    proof = ProofRecord(
        intent_id=intent_id,
        signature_b64=payload["signature"],
        status="approved",
        message="Approved",
        latency_ms=latency_ms,
    )
    poia_store.proofs[intent_id] = proof
    log_poia_event(
        event="passkey_complete",
        intent_id=intent_id,
        user_id=user["id"],
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=intent_record.intent_body.get("action"),
        status="approved",
        created_at=intent_record.created_at,
        expires_at=challenge_record.expires_at,
        method="webauthn",
        latency_ms=latency_ms,
    )
    log_audit(user["id"], "poia_approve", f"Intent {intent_id} approved via WebAuthn")
    webauthn_state_store.clear(token)
    request.session.pop("poia_assertion_token", None)
    request.session.pop("poia_intent_id", None)

    return Response(content=json.dumps({"redirect_url": f"/poia/execute/{intent_id}"}), media_type="application/json")


@router.get("/poia/status")
def poia_status(intent_id: str, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied"}), media_type="application/json", status_code=401)
    intent_record = poia_store.intents.get(intent_id)
    if not intent_record or intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return Response(content=json.dumps({"status": "denied"}), media_type="application/json", status_code=404)
    challenge_record = poia_store.challenges.get(intent_id)
    if challenge_record and int(time.time()) > int(challenge_record.expires_at):
        return Response(content=json.dumps({"status": "expired"}), media_type="application/json")
    proof = poia_store.proofs.get(intent_id)
    status = proof.status if proof else "pending"
    return Response(content=json.dumps({"status": status}), media_type="application/json")


@router.get("/poia/execute/{intent_id}")
def poia_execute(intent_id: str, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    proof = poia_store.proofs.get(intent_id)
    if not intent_record or not challenge_record or not proof or proof.status != "approved":
        return render(request, "result.html", {"status": "Rejected", "message": "Intent not approved."})
    if int(time.time()) > int(challenge_record.expires_at):
        return render(request, "result.html", {"status": "Rejected", "message": "Intent expired."})

    action = intent_record.intent_body["action"]
    log_poia_event(
        event="intent_execute",
        intent_id=intent_id,
        user_id=user["id"],
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=action,
        status="approved",
        created_at=intent_record.created_at,
        expires_at=challenge_record.expires_at,
    )
    if action == "transfer":
        return execute_transfer(request, user, intent_record.intent_body)
    if action == "beneficiary_add":
        return execute_beneficiary_add(request, user, intent_record.intent_body)
    if action in {"withdrawal", "deposit"}:
        return execute_cash(request, user, intent_record.intent_body)
    if action == "statement_export":
        scope = intent_record.intent_body.get("scope", {})
        query = urllib.parse.urlencode(
            {
                "account_id": scope.get("account_id", ""),
                "txn_type": scope.get("txn_type", ""),
                "date_from": scope.get("date_from", ""),
                "date_to": scope.get("date_to", ""),
            }
        )
        download_url = f"/statements.csv?{query}&poia=1" if query else "/statements.csv?poia=1"
        return render(
            request,
            "statements_download.html",
            {"download_url": download_url, "redirect_url": "/statements"},
        )
    if action == "admin_audit_view":
        return RedirectResponse(url="/admin/audit?poia=1", status_code=302)
    if action == "admin_mfa_view":
        return RedirectResponse(url="/admin/mfa?poia=1", status_code=302)

    return render(request, "result.html", {"status": "Approved", "message": "Action completed."})


@router.get("/api/poia/pending")
def api_poia_pending(user_id: int, force: int = 0) -> Response:
    with db_connect() as conn:
        user = conn.execute("SELECT poia_zt_enabled FROM users WHERE id = ?", (user_id,)).fetchone()
    if not force and (not user or not user["poia_zt_enabled"]):
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json")
    now = int(time.time())
    pending = []
    for intent_id, intent_record in poia_store.intents.items():
        challenge = poia_store.challenges.get(intent_id)
        proof = poia_store.proofs.get(intent_id)
        if not challenge or not intent_record:
            continue
        if int(challenge.expires_at) <= now:
            continue
        if intent_record.intent_body.get("context", {}).get("user_id") != user_id:
            continue
        if proof and proof.status != "pending":
            continue
        pending.append((intent_id, intent_record, challenge))
    if not pending:
        return Response(content=json.dumps({"status": "none"}), media_type="application/json")
    intent_id, intent_record, challenge = pending[0]
    log_poia_event(
        event="pending_served",
        intent_id=intent_id,
        user_id=user_id,
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=intent_record.intent_body.get("action"),
        status="pending",
        created_at=intent_record.created_at,
        expires_at=challenge.expires_at,
        method="zt_authenticator",
    )
    proof_payload = build_proof_payload(intent_record.intent_body, challenge.nonce, challenge.expires_at)
    proof_hash = hashlib.sha256(proof_payload).hexdigest()
    body_hash = intent_hash(intent_record.intent_body)
    payload = {
        "status": "pending",
        "intent_id": intent_id,
        "intent": intent_record.intent_body,
        "nonce": challenge.nonce,
        "rp_id": intent_record.intent_body.get("context", {}).get("rp_id"),
        "intent_hash": proof_hash,
        "intent_body_hash": body_hash,
        "expires_at": int(challenge.expires_at),
        "expires_in": max(0, int(challenge.expires_at) - now),
    }
    return Response(content=json.dumps(payload), media_type="application/json")


@router.post("/api/poia/approve")
def api_poia_approve(payload: dict) -> Response:
    intent_id = payload.get("intent_id")
    device_id_raw = payload.get("device_id")
    rp_id = (payload.get("rp_id") or "").strip()
    nonce = (payload.get("nonce") or "").strip()
    signature = (payload.get("signature") or "").strip()
    intent_hash_override = (payload.get("intent_hash") or "").strip()
    if not intent_id or not device_id_raw or not rp_id or not nonce or not signature:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_fields"}), media_type="application/json", status_code=400)
    try:
        device_id = int(device_id_raw)
    except (TypeError, ValueError):
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_device"}), media_type="application/json", status_code=400)

    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "intent_invalid"}), media_type="application/json", status_code=404)
    proof = poia_store.proofs.get(intent_id)
    if proof and proof.status != "pending":
        return Response(content=json.dumps({"status": "denied", "reason": "replay"}), media_type="application/json", status_code=409)
    if intent_record.intent_body.get("context", {}).get("rp_id") != rp_id:
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="rp_mismatch",
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return Response(content=json.dumps({"status": "denied", "reason": "rp_mismatch"}), media_type="application/json", status_code=400)
    if challenge.nonce != nonce:
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="nonce_mismatch",
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return Response(content=json.dumps({"status": "denied", "reason": "nonce_mismatch"}), media_type="application/json", status_code=400)
    if int(time.time()) > int(challenge.expires_at):
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="expired",
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return Response(content=json.dumps({"status": "denied", "reason": "expired"}), media_type="application/json", status_code=400)

    from ..security import verify_p256_signature
    proof_payload = build_proof_payload(intent_record.intent_body, challenge.nonce, challenge.expires_at)
    proof_hash = hashlib.sha256(proof_payload).hexdigest()
    body_hash = intent_hash(intent_record.intent_body)
    if intent_hash_override and intent_hash_override not in {proof_hash, body_hash}:
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="hash_mismatch",
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return Response(content=json.dumps({"status": "denied", "reason": "hash_mismatch"}), media_type="application/json", status_code=400)
    primary_message = f"{proof_hash}|{device_id}|{rp_id}|{nonce}".encode("utf-8")
    fallback_message = f"{nonce}|{device_id}|{rp_id}|{proof_hash}".encode("utf-8")
    alt_primary_message = f"{body_hash}|{device_id}|{rp_id}|{nonce}".encode("utf-8")
    alt_fallback_message = f"{nonce}|{device_id}|{rp_id}|{body_hash}".encode("utf-8")

    from ..db import db_connect

    with db_connect() as conn:
        device_key = conn.execute(
            "SELECT * FROM device_keys WHERE device_id = ? AND rp_id = ? ORDER BY created_at DESC LIMIT 1",
            (device_id, rp_id),
        ).fetchone()
    if not device_key or device_key["key_type"] != "p256":
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason="device_not_enrolled",
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return Response(content=json.dumps({"status": "denied", "reason": "device_not_enrolled"}), media_type="application/json", status_code=400)
    if not verify_p256_signature(device_key["public_key"], primary_message, signature):
        if not verify_p256_signature(device_key["public_key"], fallback_message, signature):
            if verify_p256_signature(device_key["public_key"], alt_primary_message, signature) or verify_p256_signature(
                device_key["public_key"], alt_fallback_message, signature
            ):
                pass
            else:
                log_poia_event(
                    event="intent_approve",
                    intent_id=intent_id,
                    user_id=intent_record.intent_body.get("context", {}).get("user_id"),
                    rp_id=rp_id,
                    action=intent_record.intent_body.get("action"),
                    status="denied",
                    reason="invalid_signature",
                    created_at=intent_record.created_at,
                    expires_at=challenge.expires_at,
                    method="zt_authenticator",
                )
                return Response(content=json.dumps({"status": "denied", "reason": "invalid_signature"}), media_type="application/json", status_code=400)

    latency_ms = int((time.time() - intent_record.created_at) * 1000)
    poia_store.proofs[intent_id] = ProofRecord(
        intent_id=intent_id,
        signature_b64=signature,
        status="approved",
        message="Approved",
        latency_ms=latency_ms,
    )
    log_poia_event(
        event="intent_approve",
        intent_id=intent_id,
        user_id=intent_record.intent_body.get("context", {}).get("user_id"),
        rp_id=rp_id,
        action=intent_record.intent_body.get("action"),
        status="approved",
        created_at=intent_record.created_at,
        expires_at=challenge.expires_at,
        method="zt_authenticator",
        latency_ms=latency_ms,
    )
    log_audit(intent_record.intent_body.get("context", {}).get("user_id"), "poia_approve", f"Intent {intent_id} approved via ZT-Authenticator")
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.post("/api/poia/deny")
def api_poia_deny(payload: dict) -> Response:
    intent_id = payload.get("intent_id") or payload.get("intentId") or payload.get("id")
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_intent"}), media_type="application/json", status_code=400)
    proof = poia_store.proofs.get(intent_id)
    if proof:
        proof.status = "denied"
        proof.message = "Denied"
    log_poia_event(
        event="intent_deny",
        intent_id=intent_id,
        user_id=(poia_store.intents.get(intent_id).intent_body.get("context", {}).get("user_id")
                 if poia_store.intents.get(intent_id) else None),
        rp_id=(poia_store.intents.get(intent_id).intent_body.get("context", {}).get("rp_id")
               if poia_store.intents.get(intent_id) else None),
        action=(poia_store.intents.get(intent_id).intent_body.get("action")
                if poia_store.intents.get(intent_id) else None),
        status="denied",
        reason=payload.get("reason") or "user_denied",
        created_at=(poia_store.intents.get(intent_id).created_at
                    if poia_store.intents.get(intent_id) else None),
        expires_at=(poia_store.challenges.get(intent_id).expires_at
                    if poia_store.challenges.get(intent_id) else None),
        method="zt_authenticator",
    )
    log_audit(
        poia_store.intents.get(intent_id).intent_body.get("context", {}).get("user_id")
        if poia_store.intents.get(intent_id) else None,
        "poia_deny",
        f"Intent {intent_id} denied",
    )
    return Response(content=json.dumps({"status": "denied"}), media_type="application/json")


@router.post("/api/poia/test/intent")
def api_poia_test_intent(payload: dict) -> Response:
    if not POIA_TEST_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    action = (payload.get("action") or "transfer").strip()
    scope = payload.get("scope") or {"amount": 100.0, "currency": "USD", "account_id": 1}
    context = payload.get("context") or {"rp_id": "poia-demo-bank", "user_id": 1}
    intent_id = create_poia_intent(action=action, scope=scope, context=context)
    challenge = poia_store.challenges.get(intent_id)
    return Response(
        content=json.dumps(
            {
                "status": "ok",
                "intent_id": intent_id,
                "nonce": challenge.nonce if challenge else "",
                "expires_at": int(challenge.expires_at) if challenge else 0,
                "expires_in": INTENT_TTL_SECONDS,
            }
        ),
        media_type="application/json",
    )


@router.post("/api/poia/test/approve")
def api_poia_test_approve(payload: dict) -> Response:
    if not POIA_TEST_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    intent_id = payload.get("intent_id")
    scenario = payload.get("scenario") or ""
    force_status = payload.get("force_status") or "approved"
    reason = payload.get("reason") or ""
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_intent"}), media_type="application/json", status_code=400)
    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "intent_invalid"}), media_type="application/json", status_code=404)
    if int(time.time()) > int(challenge.expires_at):
        force_status = "denied"
        reason = reason or "expired"
    latency_ms = int((time.time() - intent_record.created_at) * 1000)
    status = "approved" if force_status == "approved" else "denied"
    poia_store.proofs[intent_id] = ProofRecord(
        intent_id=intent_id,
        signature_b64="test-mode",
        status=status,
        message="Approved" if status == "approved" else "Denied",
        latency_ms=latency_ms,
    )
    log_poia_event(
        event="intent_approve",
        intent_id=intent_id,
        user_id=intent_record.intent_body.get("context", {}).get("user_id"),
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=intent_record.intent_body.get("action"),
        status=status,
        reason=reason or ("synthetic" if status == "approved" else "denied"),
        created_at=intent_record.created_at,
        expires_at=challenge.expires_at,
        method="test_mode",
        latency_ms=latency_ms,
        scenario=scenario,
    )
    return Response(content=json.dumps({"status": status}), media_type="application/json")


@router.post("/api/poia/telemetry")
def api_poia_telemetry(payload: dict) -> Response:
    event = (payload.get("event") or "").strip()
    if not event:
        return Response(content=json.dumps({"status": "ignored"}), media_type="application/json")
    intent_id = payload.get("intent_id")
    user_id = payload.get("user_id")
    rp_id = payload.get("rp_id")
    method = payload.get("method")
    client_ts = payload.get("client_ts")
    scenario = payload.get("scenario")
    log_poia_event(
        event=event,
        intent_id=intent_id,
        user_id=int(user_id) if user_id is not None else None,
        rp_id=rp_id,
        status=payload.get("status"),
        reason=payload.get("reason"),
        method=method,
        client_ts=client_ts,
        scenario=scenario,
        payload={k: v for k, v in payload.items() if k not in {"event", "intent_id", "user_id", "rp_id", "method"}},
    )
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")
