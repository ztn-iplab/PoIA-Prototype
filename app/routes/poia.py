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
    canonical_json,
    create_poia_intent,
    get_current_user,
    intent_hash,
    log_audit,
    poia_store,
    render,
    require_login,
)
from ..poia_metrics import log_poia_event
from ..track_a_recorder import track_a_recorder
from ..model import ProofRecord
from ..model import intent_mismatch_reason, nonce_mismatch_reason
from ..db import db_connect
from ..downstream_client import downstream_client
from ..routes.banking import (
    execute_beneficiary_add,
    execute_cash,
    execute_statements_export,
    execute_transfer,
)
from ..webauthn_utils import get_webauthn_server, load_credentials, webauthn_state_store
from ..settings import POIA_EXPERIMENT_MODE, POIA_TEST_MODE, INTENT_TTL_SECONDS
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
    started_ns = time.perf_counter_ns()
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
        response = Response(content=json.dumps({"error": "poia_expired"}), media_type="application/json", status_code=400)
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge_record.nonce,
            rejection_reason="expired",
            http_status=response.status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
        return response

    credentials, _descriptors = load_credentials(user["id"])
    if not credentials:
        response = Response(content=json.dumps({"error": "no_passkey"}), media_type="application/json", status_code=404)
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge_record.nonce,
            rejection_reason="no_passkey",
            http_status=response.status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
        return response

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
    started_ns = time.perf_counter_ns()
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
        response = Response(
            content=json.dumps({"error": "poia_verify_failed", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge_record.nonce,
            rejection_reason="verify_failed",
            http_status=response.status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
        return response

    now = time.time()
    latency_ms = int((now - intent_record.created_at) * 1000)
    proof = ProofRecord(
        intent_id=intent_id,
        signature_b64=payload["signature"],
        status="approved",
        message="Approved",
        latency_ms=latency_ms,
    )
    approved, approval_reason = poia_store.approve_proof(proof, now)
    if not approved:
        log_poia_event(
            event="passkey_complete",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason=approval_reason,
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
            method="webauthn",
            latency_ms=latency_ms,
        )
        response = Response(
            content=json.dumps({"error": "poia_approval_denied", "reason": approval_reason}),
            media_type="application/json",
            status_code=409 if approval_reason == "replay" else 400,
        )
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge_record.nonce,
            rejection_reason=approval_reason,
            http_status=response.status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
        return response
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
    started_ns = time.perf_counter_ns()
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    existing_intent = poia_store.intents.get(intent_id)
    existing_challenge = poia_store.challenges.get(intent_id)
    if track_a_recorder.enabled and existing_intent is not None:
        before = track_a_recorder.capture_state(
            user["id"],
            existing_intent.intent_body.get("action", "unknown"),
            existing_intent.intent_body.get("scope", {}),
        )
    else:
        before = {"digest": "unavailable"}
    reserved, reason, intent_record, challenge_record = poia_store.reserve_execution(
        intent_id, user["id"], time.time()
    )
    if not reserved or intent_record is None or challenge_record is None:
        log_poia_event(
            event="intent_execute",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=(intent_record.intent_body.get("context", {}).get("rp_id") if intent_record else None),
            action=(intent_record.intent_body.get("action") if intent_record else None),
            status="denied",
            reason=reason,
            created_at=(intent_record.created_at if intent_record else None),
            expires_at=(challenge_record.expires_at if challenge_record else None),
        )
        messages = {
            "expired": "Intent expired.",
            "proof_consumed": "Intent proof has already been used.",
            "principal_mismatch": "Intent belongs to another user.",
        }
        response = render(
            request,
            "result.html",
            {"status": "Rejected", "message": messages.get(reason, "Intent not approved.")},
        )
        if track_a_recorder.enabled:
            body = (
                intent_record.intent_body
                if intent_record is not None
                else {
                    "action": "unknown",
                    "scope": {},
                    "context": {"user_id": user["id"], "rp_id": None},
                }
            )
            after = (
                track_a_recorder.capture_state(
                    user["id"], body.get("action", "unknown"), body.get("scope", {})
                )
                if intent_record is not None
                else before
            )
            track_a_recorder.record(
                request=request,
                intent_id=intent_id,
                intent_body=body,
                nonce=(challenge_record.nonce if challenge_record else None),
                expected_decision=track_a_recorder.expected_decision_for(request),
                decision="reject",
                rejection_reason=reason,
                http_status=response.status_code,
                started_ns=started_ns,
                before=before,
                after=after,
                latency_ms=(
                    max(0.0, (time.time() - intent_record.created_at) * 1000.0)
                    if intent_record is not None
                    else None
                ),
                latency_started_at_utc=(
                    intent_record.created_at if intent_record is not None else None
                ),
            )
        return response

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
        response = execute_transfer(request, user, intent_record.intent_body)
    elif action == "beneficiary_add":
        response = execute_beneficiary_add(request, user, intent_record.intent_body)
    elif action in {"withdrawal", "deposit"}:
        response = execute_cash(request, user, intent_record.intent_body)
    elif action == "statement_export":
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
        response = render(
            request,
            "statements_download.html",
            {"download_url": download_url, "redirect_url": "/statements"},
        )
    elif action == "admin_audit_view":
        response = RedirectResponse(url="/admin/audit?poia=1", status_code=302)
    elif action == "admin_mfa_view":
        response = RedirectResponse(url="/admin/mfa?poia=1", status_code=302)
    else:
        response = render(request, "result.html", {"status": "Approved", "message": "Action completed."})

    if track_a_recorder.enabled:
        after = track_a_recorder.capture_state(
            user["id"], action, intent_record.intent_body.get("scope", {})
        )
        track_a_recorder.record(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge_record.nonce,
            expected_decision=track_a_recorder.expected_decision_for(request),
            decision="accept",
            rejection_reason=None,
            http_status=response.status_code,
            started_ns=started_ns,
            before=before,
            after=after,
            latency_ms=max(0.0, (time.time() - intent_record.created_at) * 1000.0),
            latency_started_at_utc=intent_record.created_at,
        )
    return response


@router.post("/api/poia/experiment/execute")
def api_poia_experiment_execute(payload: dict, request: Request) -> Response:
    """Execute an explicitly supplied intent through the production semantic gate."""
    if not POIA_EXPERIMENT_MODE:
        return Response(
            content=json.dumps({"status": "disabled"}),
            media_type="application/json",
            status_code=403,
        )
    started_ns = time.perf_counter_ns()
    user = get_current_user(request)
    if not require_login(user):
        return Response(
            content=json.dumps({"status": "denied", "reason": "unauthorized"}),
            media_type="application/json",
            status_code=401,
        )
    intent_id = str(payload.get("intent_id") or "")
    requested = payload.get("requested_intent")
    if not intent_id or not isinstance(requested, dict):
        return Response(
            content=json.dumps({"status": "denied", "reason": "missing_fields"}),
            media_type="application/json",
            status_code=400,
        )
    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if intent_record is None or challenge is None:
        return Response(
            content=json.dumps({"status": "denied", "reason": "intent_invalid"}),
            media_type="application/json",
            status_code=404,
        )
    action = requested.get("action", "unknown")
    scope = requested.get("scope", {})
    requested_context = requested.get("context", {})
    workflow_id = requested_context.get("workflow_id")
    before = (
        track_a_recorder.capture_state(user["id"], action, scope)
        if track_a_recorder.enabled
        else {"digest": "unavailable"}
    )
    delegated_principal = requested_context.get("on_behalf_of")
    if track_a_recorder.enabled and action == "ledger_post" and delegated_principal:
        before = track_a_recorder.attach_external_state(
            before, "downstream_ledger", downstream_client.state(str(delegated_principal))
        )
    workflow_reason = None
    semantic_reason = intent_mismatch_reason(intent_record.intent_body, requested)
    if semantic_reason:
        workflow_reason = semantic_reason
    elif workflow_id:
        scope_hash = hashlib.sha256(canonical_json(scope)).hexdigest()
        with db_connect() as conn:
            workflow = conn.execute(
                "SELECT * FROM poia_workflows WHERE workflow_id = ?",
                (workflow_id,),
            ).fetchone()
        if workflow is None:
            workflow_reason = "workflow_invalid"
        elif workflow["user_id"] != user["id"]:
            workflow_reason = "workflow_principal_mismatch"
        elif workflow["status"] != "pending":
            workflow_reason = "workflow_consumed"
        elif workflow["action"] != action or workflow["scope_hash"] != scope_hash:
            workflow_reason = "workflow_scope_mismatch"
    if action not in {"transfer", "ledger_post"}:
        reserved, reason = False, "unsupported_action"
    elif workflow_reason:
        reserved, reason = False, workflow_reason
    else:
        reserved, reason, _, _ = poia_store.reserve_execution(
            intent_id, user["id"], time.time(), requested
        )
    if reserved:
        if workflow_id:
            with db_connect() as conn:
                updated = conn.execute(
                    "UPDATE poia_workflows SET status = 'consumed', consumed_at = ? "
                    "WHERE workflow_id = ? AND status = 'pending'",
                    (int(time.time()), workflow_id),
                ).rowcount
            if updated != 1:
                reserved = False
                reason = "workflow_consumed"
    if reserved:
        if action == "transfer":
            response = execute_transfer(request, user, requested)
            decision = "accept"
            rejection_reason = None
        else:
            downstream_status, downstream_body = downstream_client.post_ledger_entry(
                requested, intent_id
            )
            response = Response(
                content=json.dumps(downstream_body),
                media_type="application/json",
                status_code=downstream_status,
            )
            decision = "accept" if downstream_status == 201 else "reject"
            rejection_reason = (
                None if decision == "accept" else downstream_body.get("reason", "downstream_denied")
            )
    else:
        response = Response(
            content=json.dumps({"status": "denied", "reason": reason}),
            media_type="application/json",
            status_code=409 if reason == "proof_consumed" else 400,
        )
        decision = "reject"
        rejection_reason = reason
    if track_a_recorder.enabled:
        after = track_a_recorder.capture_state(user["id"], action, scope)
        if action == "ledger_post" and delegated_principal:
            after = track_a_recorder.attach_external_state(
                after, "downstream_ledger", downstream_client.state(str(delegated_principal))
            )
        track_a_recorder.record(
            request=request,
            intent_id=intent_id,
            intent_body=requested,
            nonce=challenge.nonce,
            expected_decision=track_a_recorder.expected_decision_for(request),
            decision=decision,
            rejection_reason=rejection_reason,
            http_status=response.status_code,
            started_ns=started_ns,
            before=before,
            after=after,
            approved_intent_body=intent_record.intent_body,
            requested_intent_body=requested,
        )
    return response


@router.post("/api/poia/experiment/delegation/start")
def api_poia_experiment_delegation_start(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(
            content=json.dumps({"status": "disabled"}),
            media_type="application/json",
            status_code=403,
        )
    user = get_current_user(request)
    if not require_login(user):
        return Response(
            content=json.dumps({"status": "denied", "reason": "unauthorized"}),
            media_type="application/json",
            status_code=401,
        )
    scope = payload.get("scope")
    if not isinstance(scope, dict) or not scope.get("object_id"):
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_delegation"}),
            media_type="application/json",
            status_code=400,
        )
    intent_id = create_poia_intent(
        action="ledger_post",
        scope=scope,
        context={
            "rp_id": "poia-ledger",
            "user_id": user["id"],
            "on_behalf_of": f"experiment-principal-{user['id']}",
        },
    )
    return Response(
        content=json.dumps(
            {
                "status": "pending",
                "intent_id": intent_id,
                "approval_url": f"/poia/approve/{intent_id}",
            }
        ),
        media_type="application/json",
        status_code=201,
    )


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


@router.post("/api/poia/experiment/token/issue")
def api_poia_experiment_token_issue(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied", "reason": "unauthorized"}), media_type="application/json", status_code=401)
    intended_action = str(payload.get("intended_action") or "deploy_config")
    if intended_action not in {"deploy_config", "api_key_rotate"}:
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_action"}), media_type="application/json", status_code=400)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + 900
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO experiment_bearer_tokens "
            "(token_hash, user_id, token_scope, intended_action, expires_at, created_at) "
            "VALUES (?, ?, 'high_risk_api', ?, ?, ?)",
            (token_hash, user["id"], intended_action, expires_at, int(time.time())),
        )
    return Response(
        content=json.dumps(
            {
                "status": "issued",
                "access_token": raw_token,
                "token_type": "Bearer",
                "scope": "high_risk_api",
                "intended_action": intended_action,
                "expires_at": expires_at,
            }
        ),
        media_type="application/json",
        status_code=201,
    )


@router.post("/api/poia/experiment/token/intent/start")
def api_poia_experiment_token_intent_start(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied", "reason": "unauthorized"}), media_type="application/json", status_code=401)
    action = str(payload.get("action") or "")
    scope = payload.get("scope")
    if action not in {"deploy_config", "api_key_rotate"} or not isinstance(scope, dict):
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_action"}), media_type="application/json", status_code=400)
    intent_id = create_poia_intent(
        action=action,
        scope=scope,
        context={"rp_id": "poia-api", "user_id": user["id"]},
    )
    return Response(
        content=json.dumps(
            {"status": "pending", "intent_id": intent_id, "approval_url": f"/poia/approve/{intent_id}"}
        ),
        media_type="application/json",
        status_code=201,
    )


@router.post("/api/poia/experiment/token/action")
def api_poia_experiment_token_action(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    started_ns = time.perf_counter_ns()
    raw_token = _bearer_token(request)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest() if raw_token else ""
    with db_connect() as conn:
        token = conn.execute(
            "SELECT * FROM experiment_bearer_tokens WHERE token_hash = ? AND expires_at >= ?",
            (token_hash, int(time.time())),
        ).fetchone()
    if token is None:
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_token"}), media_type="application/json", status_code=401)
    action = str(payload.get("action") or "")
    scope = payload.get("scope")
    if action not in {"deploy_config", "api_key_rotate"} or not isinstance(scope, dict) or not scope.get("object_id"):
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_action"}), media_type="application/json", status_code=400)
    configuration = (
        track_a_recorder.manifest.get("configuration")
        if track_a_recorder.enabled
        else "poia_webauthn"
    )
    requested = {
        "action": action,
        "scope": scope,
        "context": {"rp_id": "poia-api", "user_id": token["user_id"]},
        "constraints": {"expires_in_seconds": INTENT_TTL_SECONDS},
    }
    intent_id = str(payload.get("intent_id") or "")
    challenge = poia_store.challenges.get(intent_id)
    intent_record = poia_store.intents.get(intent_id)
    before = (
        track_a_recorder.capture_state(token["user_id"], action, scope)
        if track_a_recorder.enabled
        else {"digest": "unavailable"}
    )
    if configuration == "session_only":
        accepted, reason = True, "session_token_accepted"
    elif intent_record is None or challenge is None:
        accepted, reason = False, "proof_missing"
    else:
        accepted, reason, _, _ = poia_store.reserve_execution(
            intent_id, token["user_id"], time.time(), requested
        )
    if accepted:
        with db_connect() as conn:
            conn.execute(
                "INSERT INTO experiment_api_operations (user_id, action, object_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (token["user_id"], action, str(scope["object_id"]), int(time.time())),
            )
        response = Response(content=json.dumps({"status": "accepted"}), media_type="application/json", status_code=201)
        decision, rejection_reason = "accept", None
    else:
        response = Response(content=json.dumps({"status": "denied", "reason": reason}), media_type="application/json", status_code=403)
        decision, rejection_reason = "reject", reason
    if track_a_recorder.enabled:
        after = track_a_recorder.capture_state(token["user_id"], action, scope)
        approved_body = (
            intent_record.intent_body
            if intent_record
            else {
                "action": token["intended_action"],
                "scope": {"token_scope": token["token_scope"]},
                "context": {"rp_id": "poia-api", "user_id": token["user_id"]},
                "constraints": {"expires_at": token["expires_at"]},
            }
        )
        track_a_recorder.record(
            request=request,
            intent_id=intent_id or f"baseline-{token_hash[:16]}",
            intent_body=requested,
            nonce=(challenge.nonce if challenge else None),
            expected_decision=track_a_recorder.expected_decision_for(request),
            decision=decision,
            rejection_reason=rejection_reason,
            http_status=response.status_code,
            started_ns=started_ns,
            before=before,
            after=after,
            approved_intent_body=approved_body,
            requested_intent_body=requested,
        )
    return response


@router.post("/api/poia/experiment/workflow/start")
def api_poia_experiment_workflow_start(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(
            content=json.dumps({"status": "disabled"}),
            media_type="application/json",
            status_code=403,
        )
    user = get_current_user(request)
    if not require_login(user):
        return Response(
            content=json.dumps({"status": "denied", "reason": "unauthorized"}),
            media_type="application/json",
            status_code=401,
        )
    action = payload.get("action")
    scope = payload.get("scope")
    if action != "transfer" or not isinstance(scope, dict):
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_workflow"}),
            media_type="application/json",
            status_code=400,
        )
    workflow_id = secrets.token_urlsafe(12)
    scope_hash = hashlib.sha256(canonical_json(scope)).hexdigest()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO poia_workflows "
            "(workflow_id, user_id, action, scope_hash, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (workflow_id, user["id"], action, scope_hash, int(time.time())),
        )
    intent_id = create_poia_intent(
        action=action,
        scope=scope,
        context={
            "rp_id": "poia-demo-bank",
            "user_id": user["id"],
            "workflow_id": workflow_id,
        },
    )
    return Response(
        content=json.dumps(
            {
                "status": "pending",
                "workflow_id": workflow_id,
                "intent_id": intent_id,
                "approval_url": f"/poia/approve/{intent_id}",
            }
        ),
        media_type="application/json",
        status_code=201,
    )


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
def api_poia_approve(payload: dict, request: Request) -> Response:
    started_ns = time.perf_counter_ns()
    intent_id = payload.get("intent_id")
    device_id_raw = payload.get("device_id")
    rp_id = (payload.get("rp_id") or "").strip()
    nonce = (payload.get("nonce") or "").strip()
    signature = (payload.get("signature") or "").strip()
    intent_hash_override = (payload.get("intent_hash") or "").strip()
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_fields"}), media_type="application/json", status_code=400)

    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "intent_invalid"}), media_type="application/json", status_code=404)

    def deny(reason: str, status_code: int = 400) -> Response:
        response = Response(
            content=json.dumps({"status": "denied", "reason": reason}),
            media_type="application/json",
            status_code=status_code,
        )
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge.nonce,
            rejection_reason=reason,
            http_status=status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
        return response

    if not device_id_raw or not rp_id or not nonce or not signature:
        return deny("missing_fields")
    try:
        device_id = int(device_id_raw)
    except (TypeError, ValueError):
        return deny("invalid_device")
    proof = poia_store.proofs.get(intent_id)
    if proof and proof.status != "pending":
        return deny("replay", 409)
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
        return deny("rp_mismatch")
    if nonce_mismatch_reason(challenge, nonce):
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
        return deny("nonce_mismatch")
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
        return deny("expired")

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
        return deny("hash_mismatch")
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
        return deny("device_not_enrolled")
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
                return deny("invalid_signature")

    now = time.time()
    latency_ms = int((now - intent_record.created_at) * 1000)
    approved, approval_reason = poia_store.approve_proof(ProofRecord(
        intent_id=intent_id,
        signature_b64=signature,
        status="approved",
        message="Approved",
        latency_ms=latency_ms,
    ), now)
    if not approved:
        return deny(approval_reason, 409 if approval_reason == "replay" else 400)
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
def api_poia_deny(payload: dict, request: Request) -> Response:
    started_ns = time.perf_counter_ns()
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
    response = Response(content=json.dumps({"status": "denied"}), media_type="application/json")
    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if intent_record is not None:
        track_a_recorder.record_rejection(
            request=request,
            intent_id=intent_id,
            intent_body=intent_record.intent_body,
            nonce=challenge.nonce if challenge else None,
            rejection_reason=payload.get("reason") or "user_denied",
            http_status=response.status_code,
            started_ns=started_ns,
            created_at=intent_record.created_at,
        )
    return response


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
    proof_record = ProofRecord(
        intent_id=intent_id,
        signature_b64="test-mode",
        status=status,
        message="Approved" if status == "approved" else "Denied",
        latency_ms=latency_ms,
    )
    if status == "approved":
        approved, approval_reason = poia_store.approve_proof(proof_record, time.time())
        if not approved:
            status = "denied"
            reason = approval_reason
    else:
        poia_store.proofs[intent_id] = proof_record
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
