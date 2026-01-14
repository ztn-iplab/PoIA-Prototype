import base64
import hashlib
import json
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import (
    build_proof_payload,
    log_audit,
    poia_store,
    render,
    require_login,
    get_current_user,
)
from ..model import ProofRecord
from ..routes.banking import (
    execute_beneficiary_add,
    execute_cash,
    execute_statements_export,
    execute_transfer,
)
from ..webauthn_utils import get_webauthn_server, load_credentials, webauthn_state_store
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
    if action == "transfer":
        return execute_transfer(request, user, intent_record.intent_body)
    if action == "beneficiary_add":
        return execute_beneficiary_add(request, user, intent_record.intent_body)
    if action in {"withdrawal", "deposit"}:
        return execute_cash(request, user, intent_record.intent_body)
    if action == "statement_export":
        return execute_statements_export(request, user, intent_record.intent_body)
    if action == "admin_audit_view":
        return RedirectResponse(url="/admin/audit?poia=1", status_code=302)
    if action == "admin_mfa_view":
        return RedirectResponse(url="/admin/mfa?poia=1", status_code=302)

    return render(request, "result.html", {"status": "Approved", "message": "Action completed."})


@router.get("/api/poia/pending")
def api_poia_pending(user_id: int) -> Response:
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
    payload = {
        "status": "pending",
        "intent_id": intent_id,
        "intent": intent_record.intent_body,
        "nonce": challenge.nonce,
        "rp_id": intent_record.intent_body.get("context", {}).get("rp_id"),
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
    if intent_record.intent_body.get("context", {}).get("rp_id") != rp_id:
        return Response(content=json.dumps({"status": "denied", "reason": "rp_mismatch"}), media_type="application/json", status_code=400)
    if challenge.nonce != nonce:
        return Response(content=json.dumps({"status": "denied", "reason": "nonce_mismatch"}), media_type="application/json", status_code=400)
    if int(time.time()) > int(challenge.expires_at):
        return Response(content=json.dumps({"status": "denied", "reason": "expired"}), media_type="application/json", status_code=400)

    from ..security import verify_p256_signature
    proof_payload = build_proof_payload(intent_record.intent_body, challenge.nonce, challenge.expires_at)
    intent_hash = hashlib.sha256(proof_payload).hexdigest()
    if intent_hash_override and intent_hash_override != intent_hash:
        return Response(content=json.dumps({"status": "denied", "reason": "hash_mismatch"}), media_type="application/json", status_code=400)
    primary_message = f"{intent_hash}|{device_id}|{rp_id}|{nonce}".encode("utf-8")
    fallback_message = f"{nonce}|{device_id}|{rp_id}|{intent_hash}".encode("utf-8")

    from ..db import db_connect

    with db_connect() as conn:
        device_key = conn.execute(
            "SELECT * FROM device_keys WHERE device_id = ? AND rp_id = ? ORDER BY created_at DESC LIMIT 1",
            (device_id, rp_id),
        ).fetchone()
    if not device_key or device_key["key_type"] != "p256":
        return Response(content=json.dumps({"status": "denied", "reason": "device_not_enrolled"}), media_type="application/json", status_code=400)
    if not verify_p256_signature(device_key["public_key"], primary_message, signature):
        if not verify_p256_signature(device_key["public_key"], fallback_message, signature):
            return Response(content=json.dumps({"status": "denied", "reason": "invalid_signature"}), media_type="application/json", status_code=400)

    proof = poia_store.proofs.get(intent_id)
    latency_ms = int((time.time() - intent_record.created_at) * 1000)
    poia_store.proofs[intent_id] = ProofRecord(
        intent_id=intent_id,
        signature_b64=signature,
        status="approved",
        message="Approved",
        latency_ms=latency_ms,
    )
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.post("/api/poia/deny")
def api_poia_deny(payload: dict) -> Response:
    intent_id = payload.get("intent_id")
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_intent"}), media_type="application/json", status_code=400)
    proof = poia_store.proofs.get(intent_id)
    if proof:
        proof.status = "denied"
        proof.message = "Denied"
    return Response(content=json.dumps({"status": "denied"}), media_type="application/json")
