import base64
import hashlib
import json
import secrets
import time
import urllib.parse

from fastapi import APIRouter, Body, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import (
    PoIACommitmentError,
    build_proof_payload,
    canonical_sha256,
    canonical_json,
    create_poia_intent,
    get_current_user,
    intent_hash,
    log_audit,
    original_request_binding_reason,
    poia_store,
    render,
    require_login,
    verify_referent_commitments,
)
from ..human_study import (
    PARTICIPANT_RECIPIENTS,
    STUDY_DESIGN_VERSION,
    STUDY_ACTIONS,
    TRUST_SCALE_ITEMS,
    TRUST_SCALE_VALUES,
    advance_participant_session,
    append_system_event,
    apply_mutations,
    canonical_copy,
    create_trial_record,
    create_participant_session,
    ensure_cloud_resources,
    execute_cloud_study_action,
    list_cloud_resources,
    load_participant_session,
    load_trial,
    load_trial_for_intent,
    record_participant_decision,
    record_prompt_displayed,
    record_system_decision,
    reset_cloud_resources,
    select_alternate_account,
    study_account_readiness,
    participant_step,
    validate_study_mutation_plan,
    validate_study_operation,
    validate_study_ownership,
)
from ..intent_codec import build_intent
from ..poia_metrics import log_poia_event
from ..presentation import render_intent_fields, resolve_scope_display_overrides
from ..execution_grants import issue_grant
from ..durable_poia import atomic_execution
from ..track_a_recorder import track_a_recorder
from ..model import ProofRecord
from ..model import intent_mismatch_reason, nonce_mismatch_reason
from ..db import db_connect
from ..downstream_client import downstream_client
from ..routes.banking import (
    execute_account_recovery,
    execute_beneficiary_add,
    execute_beneficiary_edit,
    execute_cash,
    execute_limit_change,
    execute_statements_export,
    execute_transfer,
)
from ..webauthn_utils import get_webauthn_server, load_credentials, webauthn_state_store
from ..settings import APP_RP_ID, POIA_EXPERIMENT_MODE, POIA_TEST_MODE, INTENT_TTL_SECONDS
from fido2.utils import websafe_decode, websafe_encode

router = APIRouter()
server = get_webauthn_server()


def _study_backend_for_intent(intent_id: str) -> str | None:
    if not POIA_EXPERIMENT_MODE:
        return None
    trial = load_trial_for_intent(intent_id)
    return str(trial["signing_backend"]) if trial is not None else None


def _spontaneous_trial_for_intent(intent_id: str) -> dict | None:
    if not POIA_EXPERIMENT_MODE:
        return None
    trial = load_trial_for_intent(intent_id)
    return trial if trial is not None and trial.get("study_mode") == "spontaneous" else None


def _display_variant_for_intent(intent_id: str) -> str:
    # Dataset 2 (display-variant comparison): every real, non-study intent
    # (and every study intent from the instructed console, which has no
    # participant_session_id) resolves to "redesigned" -- only a spontaneous
    # participant-workspace trial can carry the participant's assigned
    # 'legacy' arm through to the ZT-Authenticator polling payload below.
    trial = _spontaneous_trial_for_intent(intent_id)
    if not trial or not trial.get("participant_session_id"):
        return "redesigned"
    session = load_participant_session(str(trial["participant_session_id"]))
    return str(session["display_variant"]) if session else "redesigned"


def _signing_rp_for_intent(intent_id: str, intent_record) -> str:
    # The ZT key remains bound to the enrolled application RP. A study mutation
    # may alter the represented authorization context, but never key ownership.
    if _spontaneous_trial_for_intent(intent_id) is not None:
        return APP_RP_ID
    return str(intent_record.intent_body.get("context", {}).get("rp_id") or "")


@router.get("/poia/experiment/human-study", response_class=HTMLResponse)
def poia_human_study_console(request: Request) -> HTMLResponse:
    if not POIA_EXPERIMENT_MODE:
        return render(request, "result.html", {"status": "Unavailable", "message": "Experiment mode is disabled."})
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    with db_connect() as conn:
        accounts = conn.execute(
            "SELECT id, account_type, balance FROM accounts WHERE user_id = ? ORDER BY id",
            (user["id"],),
        ).fetchall()
    ensure_cloud_resources(user["id"])
    return render(
        request,
        "human_study_console.html",
        {
            "accounts": accounts,
            "cloud_resources": list_cloud_resources(user["id"]),
            "study_readiness": study_account_readiness(user["id"]),
        },
    )


@router.get("/poia/experiment/participant", response_class=HTMLResponse)
def poia_participant_workspace(request: Request, session: str = "") -> HTMLResponse:
    if not POIA_EXPERIMENT_MODE:
        return render(request, "result.html", {"status": "Unavailable", "message": "This work session is unavailable."})
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    readiness = study_account_readiness(user["id"])
    participant_session = load_participant_session(session, user["id"]) if session else None
    if session and participant_session is None:
        return render(request, "result.html", {"status": "Unavailable", "message": "This work session could not be found."})
    with db_connect() as conn:
        accounts = conn.execute(
            "SELECT id, account_type FROM accounts WHERE user_id = ? ORDER BY id",
            (user["id"],),
        ).fetchall()
        participant_beneficiaries = conn.execute(
            "SELECT name, bank, account_number FROM beneficiaries "
            "WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user["id"],),
        ).fetchall()
    ensure_cloud_resources(user["id"])
    current = participant_step(participant_session) if participant_session and participant_session["status"] == "active" else None
    active_trial = None
    if participant_session and current:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT trial_id, intent_id FROM poia_human_study_trials "
                "WHERE participant_session_id = ? AND step_index = ?",
                (session, int(participant_session["current_step"])),
            ).fetchone()
            active_trial = dict(row) if row else None
    intent_id = str(request.query_params.get("poia_intent") or "")
    if intent_id and (not active_trial or active_trial["intent_id"] != intent_id):
        intent_id = ""
    return render(
        request,
        "participant_workspace.html",
        {
            "participant_session": participant_session,
            "participant_step": current,
            "participant_progress": int(participant_session["current_step"]) + 1 if current else 0,
            "participant_total": len(json.loads(participant_session["schedule_json"])) if participant_session else 0,
            "accounts": accounts,
            "cloud_resources": list_cloud_resources(user["id"]),
            "recipients": PARTICIPANT_RECIPIENTS,
            "participant_beneficiaries": participant_beneficiaries,
            "study_readiness": readiness,
            "active_trial": active_trial,
            "poia_intent_id": intent_id or None,
            "user_id": user["id"],
            "participant_mode": True,
            "participant_return_url": f"/poia/experiment/participant?session={urllib.parse.quote(session)}" if session else "/poia/experiment/participant",
            "display_variant": participant_session["display_variant"] if participant_session else "redesigned",
        },
    )


@router.get("/poia/experiment/participant/result", response_class=HTMLResponse)
def poia_participant_result(request: Request, session: str, step: int, download: int = 0) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    participant_session = load_participant_session(session, user["id"])
    if participant_session is None or step < 0 or step >= int(participant_session["current_step"]):
        return RedirectResponse(
            url=f"/poia/experiment/participant?session={urllib.parse.quote(session)}",
            status_code=303,
        )
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM poia_human_study_trials WHERE participant_session_id = ? "
            "AND step_index = ? AND study_mode = 'spontaneous'",
            (session, step),
        ).fetchone()
    if row is None or row["system_decision"] != "accept" or not row["execution_body"]:
        return RedirectResponse(
            url=f"/poia/experiment/participant?session={urllib.parse.quote(session)}",
            status_code=303,
        )
    execution = json.loads(row["execution_body"])
    action = str(execution.get("action") or "")
    scope = execution.get("scope", {})
    if download and action == "statement_export":
        return execute_statements_export(request, user, execution)
    if download and action == "cloud_file_download":
        name = str(scope.get("resource_name") or "study-file.txt")
        content = f"Synthetic study file\nName: {name}\nClassification: {scope.get('classification', '')}\n"
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{urllib.parse.quote(name)}.txt"'},
        )
    if action not in {"statement_export", "cloud_file_view", "cloud_file_download"}:
        return RedirectResponse(
            url=f"/poia/experiment/participant?session={urllib.parse.quote(session)}",
            status_code=303,
        )
    return render(
        request,
        "participant_result.html",
        {
            "participant_session": participant_session,
            "result_action": action,
            "result_scope": scope,
            "participant_mode": True,
            "download_url": (
                f"/poia/experiment/participant/result?session={urllib.parse.quote(session)}&step={step}&download=1"
            ),
            "continue_url": f"/poia/experiment/participant?session={urllib.parse.quote(session)}",
        },
    )


@router.get("/poia/approve/{intent_id}", response_class=HTMLResponse)
def poia_approve(request: Request, intent_id: str) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    intent_record = poia_store.intents.get(intent_id)
    challenge_record = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge_record:
        return render(request, "result.html", {"status": "Rejected", "message": "Intent expired or invalid."})
    if intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return render(request, "result.html", {"status": "Rejected", "message": "Intent belongs to another user."})

    action = intent_record.intent_body.get("action", "")
    scope = intent_record.intent_body.get("scope", {})
    context = intent_record.intent_body.get("context", {})
    return render(
        request,
        "approve.html",
        {
            "intent_id": intent_id,
            "intent": intent_record.intent_body,
            "fields": render_intent_fields(action, scope, context),
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
        "display_fields": render_intent_fields(
            intent_record.intent_body.get("action", ""),
            intent_record.intent_body.get("scope", {}),
            intent_record.intent_body.get("context", {}),
        ),
        "scope_display_overrides": resolve_scope_display_overrides(
            intent_record.intent_body.get("scope", {})
        ),
        "nonce": challenge_record.nonce,
        "expires_at": int(challenge_record.expires_at),
        "intent_id": intent_id,
    }
    study_backend = _study_backend_for_intent(intent_id)
    if study_backend:
        payload["signing_backend"] = study_backend
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

    study_backend = _study_backend_for_intent(intent_id)
    if study_backend and study_backend != "webauthn":
        return Response(
            content=json.dumps({"error": "wrong_signing_backend", "required": study_backend}),
            media_type="application/json",
            status_code=409,
        )

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
    # fido2 (pinned to 2.2.1 in requirements.txt) accepts `challenge=` directly, so the
    # WebAuthn assertion challenge is always the intent-bound digest computed above -- there
    # is no fallback path here that could silently leave state["challenge"] unbound from
    # proof_payload, which is what Intent Integrity's WebAuthn realization (Sec. VI.B1)
    # depends on. An earlier version of this call carried a try/except compatibility shim
    # for older fido2 releases that swallowed exceptions while patching the challenge onto
    # the returned objects after the fact; that shim was dead code against the pinned
    # dependency and, had it ever been exercised, could have silently produced a challenge
    # not bound to the canonical intent, so it has been removed rather than retained "just
    # in case." A future fido2 upgrade that changes this signature should fail loudly (an
    # explicit TypeError) rather than reintroduce a silent fallback.
    assertion_data, state = server.authenticate_begin(credentials, challenge=challenge)
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
            payload={"detail": type(exc).__name__},
        )
        response = Response(
            content=json.dumps({"error": "poia_verify_failed"}),
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

    binding_reason = original_request_binding_reason(intent_record)
    if binding_reason and _spontaneous_trial_for_intent(intent_id) is None:
        record_participant_decision(
            intent_id,
            "sign",
            system_decision="reject",
            rejection_reason=binding_reason,
        )
        log_poia_event(
            event="passkey_complete",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason=binding_reason,
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
            method="webauthn",
        )
        webauthn_state_store.clear(token)
        request.session.pop("poia_assertion_token", None)
        request.session.pop("poia_intent_id", None)
        return Response(
            content=json.dumps({"error": "poia_original_request_mismatch", "reason": binding_reason}),
            media_type="application/json",
            status_code=409,
        )

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
    record_participant_decision(
        intent_id,
        "sign",
        system_decision="approved",
        proof_status="approved",
    )
    webauthn_state_store.clear(token)
    request.session.pop("poia_assertion_token", None)
    request.session.pop("poia_intent_id", None)

    study_trial = load_trial_for_intent(intent_id) if POIA_EXPERIMENT_MODE else None
    if study_trial and study_trial.get("study_mode") == "spontaneous":
        redirect_url = (
            "/poia/experiment/participant?session="
            + urllib.parse.quote(str(study_trial["participant_session_id"]))
        )
    else:
        redirect_url = f"/poia/execute/{intent_id}"
    return Response(content=json.dumps({"redirect_url": redirect_url}), media_type="application/json")


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
@atomic_execution
def poia_execute(intent_id: str, request: Request) -> Response:
    started_ns = time.perf_counter_ns()
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    existing_intent = poia_store.intents.get(intent_id)
    existing_challenge = poia_store.challenges.get(intent_id)
    study_trial = load_trial_for_intent(intent_id) if POIA_EXPERIMENT_MODE else None
    if study_trial is not None:
        return render(
            request,
            "result.html",
            {
                "status": "Approval recorded",
                "message": "The controlled study execution is waiting for the facilitator.",
            },
        )
    if track_a_recorder.enabled and existing_intent is not None:
        before = track_a_recorder.capture_state(
            user["id"],
            existing_intent.intent_body.get("action", "unknown"),
            existing_intent.intent_body.get("scope", {}),
        )
    else:
        before = {"digest": "unavailable"}
    binding_reason = (
        original_request_binding_reason(existing_intent)
        if existing_intent is not None
        else None
    )
    if binding_reason:
        reserved, reason, intent_record, challenge_record = (
            False,
            binding_reason,
            existing_intent,
            existing_challenge,
        )
    else:
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

    # Referent-State Integrity (D_RSI): the proof and nonce just checked out, but
    # that only proves the signed intent is genuine -- not that what it refers to
    # is still what it referred to when it was signed. Re-check now, before any
    # state changes, and leave state untouched on a mismatch.
    referent_reason = verify_referent_commitments(intent_record.intent_body)
    if referent_reason:
        log_poia_event(
            event="intent_execute",
            intent_id=intent_id,
            user_id=user["id"],
            rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
            action=action,
            status="denied",
            reason=referent_reason,
            created_at=intent_record.created_at,
            expires_at=challenge_record.expires_at,
        )
        response = render(
            request,
            "result.html",
            {
                "status": "Rejected",
                "message": (
                    "The details behind this authorization changed after you approved it "
                    "(for example, the beneficiary's bank details were edited). Nothing was "
                    "executed. Please review the current details and try again."
                ),
            },
        )
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
                decision="reject",
                rejection_reason=referent_reason,
                http_status=response.status_code,
                started_ns=started_ns,
                before=before,
                after=after,
                latency_ms=max(0.0, (time.time() - intent_record.created_at) * 1000.0),
                latency_started_at_utc=intent_record.created_at,
            )
        return response

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
    elif action == "beneficiary_edit":
        response = execute_beneficiary_edit(request, user, intent_record.intent_body)
    elif action == "limit_change":
        response = execute_limit_change(request, user, intent_record.intent_body)
    elif action == "account_recovery":
        response = execute_account_recovery(request, user, intent_record.intent_body)
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
        grant = issue_grant(user["id"], action, scope)
        download_url = f"/statements.csv?{query}&grant={grant}"
        response = render(
            request,
            "statements_download.html",
            {"download_url": download_url, "redirect_url": "/statements"},
        )
    elif action == "admin_audit_view":
        grant = issue_grant(user["id"], action, {"resource": "audit_logs"})
        response = RedirectResponse(url=f"/admin/audit?grant={grant}", status_code=302)
    elif action == "admin_mfa_view":
        grant = issue_grant(user["id"], action, {"resource": "mfa_events"})
        response = RedirectResponse(url=f"/admin/mfa?grant={grant}", status_code=302)
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
            decision="reject" if response.headers.get("X-PoIA-Rejection-Reason") else "accept",
            rejection_reason=response.headers.get("X-PoIA-Rejection-Reason"),
            http_status=response.status_code,
            started_ns=started_ns,
            before=before,
            after=after,
            latency_ms=max(0.0, (time.time() - intent_record.created_at) * 1000.0),
            latency_started_at_utc=intent_record.created_at,
        )
    return response


@router.post("/api/poia/experiment/execute")
@atomic_execution
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
    binding_reason = original_request_binding_reason(intent_record)
    if binding_reason:
        return Response(
            content=json.dumps({"status": "denied", "reason": binding_reason}),
            media_type="application/json",
            status_code=409,
        )
    action = requested.get("action", "unknown")
    if action == "ledger_post":
        from ..remote_execution import execute_remote
        scope = requested.get("scope", {})
        principal = str(requested.get("context", {}).get("on_behalf_of") or "")
        if track_a_recorder.enabled:
            before = track_a_recorder.capture_state(user["id"], action, scope)
            before = track_a_recorder.attach_external_state(before, "downstream_ledger", downstream_client.state(principal))
        response = execute_remote(poia_store, downstream_client, intent_id, user["id"], requested)
        if track_a_recorder.enabled:
            result = json.loads(response.body)
            after = track_a_recorder.capture_state(user["id"], action, scope)
            after = track_a_recorder.attach_external_state(after, "downstream_ledger", downstream_client.state(principal))
            decision = "accept" if result.get("status") == "accepted" else ("pending" if result.get("status") == "pending" else "reject")
            track_a_recorder.record(request=request, intent_id=intent_id, intent_body=requested,
                nonce=challenge.nonce, expected_decision=track_a_recorder.expected_decision_for(request),
                decision=decision, rejection_reason=result.get("reason"), http_status=response.status_code,
                started_ns=started_ns, before=before, after=after,
                approved_intent_body=intent_record.intent_body, requested_intent_body=requested)
        return response
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
    referent_reason = verify_referent_commitments(intent_record.intent_body) if reserved else None
    if referent_reason:
        reserved = False
        reason = referent_reason
    if reserved:
        if action == "transfer":
            response = execute_transfer(request, user, intent_record.intent_body)
            rejection_reason = response.headers.get("X-PoIA-Rejection-Reason")
            decision = "reject" if rejection_reason else "accept"
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


def _participant_json(body: dict, status_code: int = 200) -> Response:
    return Response(content=json.dumps(body), media_type="application/json", status_code=status_code)


@router.post("/api/poia/experiment/participant/begin")
def api_poia_participant_begin(request: Request, payload: dict = Body(default=None)) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return _participant_json({"status": "unavailable"}, 403)
    user = get_current_user(request)
    if not require_login(user):
        return _participant_json({"status": "denied"}, 401)
    readiness = study_account_readiness(user["id"])
    if not readiness["ready"]:
        return _participant_json({"status": "not_ready", "missing": [key for key, value in readiness["checks"].items() if not value]}, 409)
    payload = payload or {}
    if (payload.get("consent") is not True or payload.get("sign_meaning") != "authorize"
            or payload.get("decline_meaning") != "do_not_authorize"):
        return _participant_json({"status": "orientation_required", "message": "Please answer both questions before beginning."}, 400)
    # Each participant begins from the same synthetic cloud state. Resetting at
    # session start preserves the previous session's final screen and evidence.
    reset_cloud_resources(user["id"])
    session = create_participant_session(user["id"], {
        "consent": True, "sign_meaning": "authorize", "decline_meaning": "do_not_authorize",
        "recorded_at": time.time(),
    })
    return _participant_json(
        {"status": "ready", "next_url": f"/poia/experiment/participant?session={urllib.parse.quote(session['session_id'])}"},
        201,
    )


def _participant_mutations(
    scenario: dict, action: str, scope: dict, alternate_account: str
) -> list[dict]:
    mutation_type = scenario["type"]
    amount = float(scope.get("amount") or 0)
    increased = round(max(amount * 10, amount + 1000), 2)
    if mutation_type == "target":
        return [{"path": "scope.external_account", "value": alternate_account}]
    if mutation_type == "beneficiary_target":
        return [{"path": "scope.account_number", "value": alternate_account}]
    if mutation_type == "scope":
        return [{"path": "scope.amount", "value": increased}]
    if mutation_type == "subtle_parameter":
        return [{"path": "scope.amount", "value": round(amount + 0.01, 2)}]
    if mutation_type == "context":
        return [{"path": "context.rp_id", "value": "poia-cloud-workspace"}]
    if mutation_type == "multiple_field":
        return [
            {"path": "scope.amount", "value": increased},
            {"path": "scope.external_account", "value": alternate_account},
        ]
    if mutation_type == "cross_operation_statement_export":
        today = time.strftime("%Y-%m-%d")
        statement_scope = {
            "account_id": str(scope["from_account"]),
            "txn_type": "",
            "date_from": f"{time.strftime('%Y')}-01-01",
            "date_to": today,
        }
        return [{"path": "action", "value": "statement_export"}, {"path": "scope", "value": statement_scope}]
    action_mutations = {
        "cross_operation_cloud_delete": "cloud_file_delete",
        "cross_operation_public_share": "cloud_file_share_public",
        "cross_operation_overwrite": "cloud_file_overwrite",
        "post_signature_cloud_delete": "cloud_file_delete",
    }
    if mutation_type in action_mutations:
        return [{"path": "action", "value": action_mutations[mutation_type]}]
    return []


@router.post("/api/poia/experiment/participant/operate")
def api_poia_participant_operate(payload: dict, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return _participant_json({"status": "unavailable"}, 403)
    user = get_current_user(request)
    if not require_login(user):
        return _participant_json({"status": "denied"}, 401)
    session_id = str(payload.get("session_id") or "")
    session = load_participant_session(session_id, user["id"])
    if session is None or session["status"] != "active":
        return _participant_json({"status": "unavailable"}, 404)
    step_index = int(session["current_step"])
    scenario = participant_step(session)
    if scenario is None:
        return _participant_json({"status": "complete"}, 409)
    with db_connect() as conn:
        existing = conn.execute(
            "SELECT intent_id FROM poia_human_study_trials WHERE participant_session_id = ? AND step_index = ?",
            (session_id, step_index),
        ).fetchone()
    if existing:
        return _participant_json({"status": "pending", "next_url": f"/poia/experiment/participant?session={urllib.parse.quote(session_id)}"}, 409)

    family = scenario["family"]
    try:
        if family == "transfer":
            action = "transfer"
            external_account = str(payload.get("external_account") or "")
            with db_connect() as conn:
                saved_accounts = {
                    str(row["account_number"])
                    for row in conn.execute(
                        "SELECT account_number FROM beneficiaries WHERE user_id = ?",
                        (user["id"],),
                    ).fetchall()
                }
            allowed_accounts = {number for number, _ in PARTICIPANT_RECIPIENTS} | saved_accounts
            if external_account not in allowed_accounts:
                raise ValueError("Choose a listed recipient")
            scope = {
                "from_account": int(payload.get("from_account")),
                "amount": float(payload.get("amount")),
                "currency": "USD",
                "external_account": external_account,
            }
        elif family == "withdrawal":
            action = "withdrawal"
            scope = {
                "account_id": int(payload.get("account_id")),
                "amount": float(payload.get("amount")),
                "currency": "USD",
            }
        elif family == "beneficiary":
            action = "beneficiary_add"
            scope = {
                "name": str(payload.get("name") or "").strip(),
                "bank": str(payload.get("bank") or "").strip(),
                "account_number": str(payload.get("account_number") or "").strip(),
            }
        elif family == "statement":
            action = "statement_export"
            scope = {
                "account_id": str(payload.get("account_id") or ""),
                "txn_type": str(payload.get("txn_type") or ""),
                "date_from": str(payload.get("date_from") or ""),
                "date_to": str(payload.get("date_to") or ""),
            }
        elif family == "cloud":
            action = str(scenario.get("operation") or "cloud_file_view")
            resources = {item["resource_id"]: item for item in list_cloud_resources(user["id"])}
            resource = resources.get(str(payload.get("resource_id") or ""))
            if resource is None:
                raise ValueError("Choose an available file")
            scope = {
                "resource_id": resource["resource_id"],
                "resource_name": resource["resource_name"],
                "classification": resource["classification"],
            }
        else:
            raise ValueError("Unsupported task")
        validate_study_operation(action, scope)
        validate_study_ownership(user["id"], action, scope)
        with db_connect() as conn:
            mutation_accounts = [
                str(row["account_number"])
                for row in conn.execute(
                    "SELECT account_number FROM beneficiaries WHERE user_id = ?",
                    (user["id"],),
                ).fetchall()
            ]
        mutation_accounts.extend(number for number, _ in PARTICIPANT_RECIPIENTS)
        selected_account = scope.get("external_account") or scope.get("account_number") or ""
        alternate = select_alternate_account(
            mutation_accounts,
            selected_account,
            f"{session_id}:{step_index}:{selected_account}",
        )
        mutations = _participant_mutations(scenario, action, scope, alternate)
        validate_study_mutation_plan(scenario["stage"], scenario["type"], mutations)

        task_body = build_intent(
            action=action,
            scope=canonical_copy(scope),
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
            ttl_seconds=INTENT_TTL_SECONDS,
        )
        displayed_body = apply_mutations(task_body, mutations) if scenario["stage"] in {"pre_display", "session_repurpose"} else canonical_copy(task_body)
        validate_study_operation(str(displayed_body["action"]), displayed_body.get("scope", {}))
        validate_study_ownership(user["id"], str(displayed_body["action"]), displayed_body.get("scope", {}))
        intent_id = create_poia_intent(
            action=str(displayed_body["action"]),
            scope=displayed_body.get("scope", {}),
            context=displayed_body.get("context", {}),
            original_request_body=canonical_copy(task_body),
        )
        intent_record = poia_store.intents[intent_id]
        trial_id = f"SP-{secrets.token_hex(12)}"
        create_trial_record(
            trial_id=trial_id,
            study_run_id=session["study_run_id"],
            participant_id=session["participant_id"],
            cohort=session.get("cohort"),
            signing_backend=scenario["backend"],
            mutation_stage=scenario["stage"],
            mutation_type=scenario["type"],
            original_request_id=str(intent_record.original_request_id),
            intent_id=intent_id,
            task_body=task_body,
            displayed_body=displayed_body,
            mutations=mutations,
            expected_participant_decision="sign" if scenario["stage"] in {"none", "post_signature"} else "refuse",
            study_mode="spontaneous",
            participant_session_id=session_id,
            step_index=step_index,
            scenario_key=scenario["key"],
        )
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        return _participant_json({"status": "invalid", "message": str(exc)}, 400)
    return _participant_json(
        {
            "status": "pending",
            "signing_backend": scenario["backend"],
            "next_url": f"/poia/experiment/participant?session={urllib.parse.quote(session_id)}&poia_intent={intent_id}" if scenario["backend"] == "webauthn" else f"/poia/experiment/participant?session={urllib.parse.quote(session_id)}",
        },
        201,
    )


@router.get("/api/poia/experiment/participant/status")
def api_poia_participant_status(session: str, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return _participant_json({"status": "denied"}, 401)
    participant_session = load_participant_session(session, user["id"])
    if participant_session is None:
        return _participant_json({"status": "unavailable"}, 404)
    if participant_session["status"] == "complete":
        return _participant_json({"status": "complete", "next_url": f"/poia/experiment/participant?session={urllib.parse.quote(session)}"})
    step_index = int(participant_session["current_step"])
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM poia_human_study_trials WHERE participant_session_id = ? AND step_index = ?",
            (session, step_index),
        ).fetchone()
    if row is None:
        return _participant_json({"status": "ready"})
    trial = dict(row)
    proof = poia_store.proofs.get(str(trial["intent_id"]))
    proof_status = proof.status if proof else "pending"
    finished = trial["participant_decision"] in {"sign", "refuse"}
    result_available = False
    if trial["participant_decision"] == "sign" and proof_status == "approved" and trial["system_decision"] == "approved":
        execution_response = api_poia_human_study_execute({"trial_id": trial["trial_id"]}, request)
        try:
            execution_result = json.loads(execution_response.body)
        except (TypeError, ValueError):
            execution_result = {}
        execution_body = json.loads(trial["displayed_body"])
        result_available = execution_result.get("status") == "accept" and execution_body.get("action") in {
            "statement_export",
            "cloud_file_view",
            "cloud_file_download",
        }
        finished = True
    if finished:
        advance_participant_session(session, step_index)
        next_url = f"/poia/experiment/participant?session={urllib.parse.quote(session)}"
        if result_available:
            next_url = (
                f"/poia/experiment/participant/result?session={urllib.parse.quote(session)}"
                f"&step={step_index}"
            )
        return _participant_json({"status": "closed", "next_url": next_url})
    challenge = poia_store.challenges.get(str(trial["intent_id"]))
    if challenge and int(time.time()) > int(challenge.expires_at):
        advance_participant_session(session, step_index)
        return _participant_json({"status": "closed", "next_url": f"/poia/experiment/participant?session={urllib.parse.quote(session)}"})
    return _participant_json({"status": "pending"})


@router.post("/api/poia/experiment/participant/debrief")
def api_poia_participant_debrief(payload: dict, request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return _participant_json({"status": "denied"}, 401)
    session_id = str(payload.get("session_id") or "")
    session = load_participant_session(session_id, user["id"])
    if session is None or session["status"] != "complete":
        return _participant_json({"status": "unavailable"}, 409)
    phase = str(payload.get("phase") or "")
    with db_connect() as conn:
        if phase == "questions":
            purpose_guess = str(payload.get("purpose_guess") or "").strip()
            noticed_unusual = str(payload.get("noticed_unusual") or "").strip()
            unusual_detail = str(payload.get("unusual_detail") or "").strip()
            semantic_fields = payload.get("semantic_fields") or []
            if isinstance(semantic_fields, str):
                semantic_fields = [semantic_fields]
            semantic_fields = sorted({str(value).strip() for value in semantic_fields})
            allowed_fields = {
                "operation", "amount", "destination", "source_account", "dates_filters",
                "file_name", "classification", "service_context", "authorizing_identity",
                "none", "other",
            }
            semantic_other = str(payload.get("semantic_other") or "").strip()
            matching_ease = str(payload.get("matching_ease") or "").strip()
            age_band = str(payload.get("age_band") or "").strip()
            banking_frequency = str(payload.get("banking_frequency") or "").strip()
            passkey_familiarity = str(payload.get("passkey_familiarity") or "").strip()
            authenticator_familiarity = str(
                payload.get("authenticator_familiarity") or ""
            ).strip()
            technical_experience = str(payload.get("technical_experience") or "").strip()
            webauthn_review_ease = str(payload.get("webauthn_review_ease") or "").strip()
            zt_review_ease = str(payload.get("zt_review_ease") or "").strip()
            backend_preference = str(payload.get("backend_preference") or "").strip()
            trust_responses = {
                key: str(payload.get(key) or "").strip() for key in TRUST_SCALE_ITEMS
            }
            preference_reason = str(payload.get("preference_reason") or "").strip()
            final_comment = str(payload.get("final_comment") or "").strip()
            experience = {
                key: str(payload.get(key) or "").strip()
                for key in (
                    "confusion", "frustration", "technical_difficulty", "decision_explanation",
                    "real_world_use_likelihood", "improvement_suggestion",
                )
            }
            if session.get("design_version") in {
                "2026-09-03-explicit-decisions-v1",
                "2026-09-04-explicit-decisions-v2",
                "2026-09-04-diverse-operations-v3",
                STUDY_DESIGN_VERSION,
            }:
                intensity = {"none", "slight", "moderate", "high", "very_high", "prefer_not"}
                if (experience["confusion"] not in intensity or experience["frustration"] not in intensity
                        or experience["technical_difficulty"] not in {"yes", "no", "unsure", "prefer_not"}
                        or len(experience["decision_explanation"]) > 1000):
                    return _participant_json({"status": "invalid"}, 400)
            if session.get("design_version") in {
                "2026-09-04-explicit-decisions-v2",
                "2026-09-04-diverse-operations-v3",
                STUDY_DESIGN_VERSION,
            }:
                if (experience["real_world_use_likelihood"] not in {
                        "very_unlikely", "unlikely", "neither", "likely", "very_likely", "prefer_not"
                    } or not experience["improvement_suggestion"]
                        or len(experience["improvement_suggestion"]) > 1000):
                    return _participant_json({"status": "invalid"}, 400)
            familiarity_values = {
                "not_familiar", "heard_of", "used_once_twice", "occasional", "regular"
            }
            review_ease_values = {
                "very_easy", "easy", "neither", "difficult", "very_difficult",
                "unable_to_judge",
            }
            if (
                not purpose_guess
                or len(purpose_guess) > 1000
                or noticed_unusual not in {"yes", "no", "unsure"}
                or len(unusual_detail) > 1000
                or not semantic_fields
                or not set(semantic_fields).issubset(allowed_fields)
                or ("none" in semantic_fields and len(semantic_fields) != 1)
                or ("other" in semantic_fields and not semantic_other)
                or len(semantic_other) > 500
                or matching_ease not in {
                    "very_easy", "easy", "neither", "difficult", "very_difficult", "did_not_check"
                }
                or age_band not in {
                    "18_24", "25_34", "35_44", "45_54", "55_64", "65_plus", "prefer_not"
                }
                or banking_frequency not in {
                    "never", "less_than_monthly", "monthly", "weekly", "several_weekly", "daily"
                }
                or passkey_familiarity not in familiarity_values
                or authenticator_familiarity not in familiarity_values
                or technical_experience not in {
                    "none", "general_it", "security_study", "security_professional", "prefer_not"
                }
                or webauthn_review_ease not in review_ease_values
                or zt_review_ease not in review_ease_values
                or backend_preference not in {
                    "webauthn", "zt_authenticator", "no_preference", "task_dependent"
                }
                or any(value not in TRUST_SCALE_VALUES for value in trust_responses.values())
                or not preference_reason
                or len(preference_reason) > 1000
                or len(final_comment) > 1000
            ):
                return _participant_json({"status": "invalid"}, 400)
            response = json.dumps(
                {
                    "purpose_guess": purpose_guess,
                    "noticed_unusual": noticed_unusual,
                    "unusual_detail": unusual_detail,
                    "semantic_fields": semantic_fields,
                    "semantic_other": semantic_other,
                    "matching_ease": matching_ease,
                    "age_band": age_band,
                    "banking_frequency": banking_frequency,
                    "passkey_familiarity": passkey_familiarity,
                    "authenticator_familiarity": authenticator_familiarity,
                    "technical_experience": technical_experience,
                    "webauthn_review_ease": webauthn_review_ease,
                    "zt_review_ease": zt_review_ease,
                    "backend_preference": backend_preference,
                    **trust_responses,
                    "preference_reason": preference_reason,
                    "final_comment": final_comment,
                    "questionnaire_version": session.get("design_version", "legacy-unversioned"),
                    **{key: value for key, value in experience.items() if value},
                },
                sort_keys=True,
            )
            conn.execute(
                "UPDATE poia_participant_sessions SET post_session_response = ?, "
                "debrief_shown_at = COALESCE(debrief_shown_at, ?) WHERE session_id = ?",
                (response, time.time(), session_id),
            )
        elif phase == "acknowledge":
            if session.get("debrief_shown_at") is None:
                return _participant_json({"status": "invalid"}, 409)
            conn.execute(
                "UPDATE poia_participant_sessions SET debriefed_at = COALESCE(debriefed_at, ?) WHERE session_id = ?",
                (time.time(), session_id),
            )
        else:
            return _participant_json({"status": "invalid"}, 400)
    return _participant_json({"status": "ok"})


@router.post("/api/poia/experiment/human-study/start")
def api_poia_human_study_start(payload: dict, request: Request) -> Response:
    """Create a live participant trial while retaining the submitted task order."""
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
    participant_id = str(payload.get("participant_id") or "").strip()
    study_run_id = str(payload.get("study_run_id") or "").strip()
    trial_id = str(payload.get("trial_id") or "").strip()
    backend = str(payload.get("signing_backend") or "").strip()
    stage = str(payload.get("mutation_stage") or "none").strip()
    mutation_type = str(payload.get("mutation_type") or "none").strip()
    mutations = payload.get("mutations") or []
    action = str(payload.get("action") or "").strip()
    scope = payload.get("scope")
    if (
        not study_run_id
        or len(study_run_id) > 64
        or not all(char.isalnum() or char in "-_." for char in study_run_id)
        or not participant_id
        or len(participant_id) > 32
        or not all(char.isalnum() or char in "-_." for char in participant_id)
    ):
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_study_identifier"}),
            media_type="application/json",
            status_code=400,
        )
    if action not in STUDY_ACTIONS or not isinstance(scope, dict):
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_study_operation"}),
            media_type="application/json",
            status_code=400,
        )
    if backend not in {"webauthn", "zt_authenticator"} or stage not in {
        "none",
        "pre_display",
        "post_signature",
        "session_repurpose",
    }:
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_study_condition"}),
            media_type="application/json",
            status_code=400,
        )
    readiness = study_account_readiness(user["id"])
    if not readiness["ready"]:
        missing = [name for name, ready in readiness["checks"].items() if not ready]
        return Response(
            content=json.dumps(
                {"status": "denied", "reason": "account_not_study_ready", "missing": missing}
            ),
            media_type="application/json",
            status_code=409,
        )
    if not isinstance(mutations, list):
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_mutations"}),
            media_type="application/json",
            status_code=400,
        )
    with db_connect() as conn:
        if not trial_id:
            backend_code = "W" if backend == "webauthn" else "Z"
            sequence = conn.execute(
                "SELECT COUNT(*) FROM poia_human_study_trials "
                "WHERE study_run_id = ? AND participant_id = ? AND signing_backend = ?",
                (study_run_id, participant_id, backend),
            ).fetchone()[0] + 1
            trial_id = f"{participant_id}-{backend_code}-T{sequence:02d}"
            while conn.execute(
                "SELECT 1 FROM poia_human_study_trials WHERE trial_id = ?", (trial_id,)
            ).fetchone():
                sequence += 1
                trial_id = f"{participant_id}-{backend_code}-T{sequence:02d}"
        if len(trial_id) > 64 or not all(
            char.isalnum() or char in "-_." for char in trial_id
        ):
            return Response(
                content=json.dumps({"status": "denied", "reason": "invalid_study_identifier"}),
                media_type="application/json",
                status_code=400,
            )
        if conn.execute(
            "SELECT 1 FROM poia_human_study_trials WHERE trial_id = ?", (trial_id,)
        ).fetchone():
            return Response(
                content=json.dumps({"status": "denied", "reason": "duplicate_trial_id"}),
                media_type="application/json",
                status_code=409,
            )
    task_body = build_intent(
        action=action,
        scope=canonical_copy(scope),
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        ttl_seconds=INTENT_TTL_SECONDS,
    )
    try:
        validate_study_operation(action, scope)
        validate_study_ownership(user["id"], action, scope)
        validate_study_mutation_plan(stage, mutation_type, mutations)
        if stage in {"pre_display", "session_repurpose"}:
            displayed_body = apply_mutations(task_body, mutations)
        else:
            displayed_body = canonical_copy(task_body)
        validate_study_operation(
            str(displayed_body.get("action") or ""),
            displayed_body.get("scope", {}),
        )
        validate_study_ownership(
            user["id"],
            str(displayed_body.get("action") or ""),
            displayed_body.get("scope", {}),
        )
        original_body = canonical_copy(task_body)
        expected_decision = "refuse" if stage in {"pre_display", "session_repurpose"} else "sign"
        intent_id = create_poia_intent(
            action=str(displayed_body["action"]),
            scope=displayed_body.get("scope", {}),
            context=displayed_body.get("context", {}),
            original_request_body=original_body,
        )
        intent_record = poia_store.intents[intent_id]
        create_trial_record(
            trial_id=trial_id,
            study_run_id=study_run_id,
            participant_id=participant_id,
            signing_backend=backend,
            mutation_stage=stage,
            mutation_type=mutation_type,
            original_request_id=str(intent_record.original_request_id),
            intent_id=intent_id,
            task_body=task_body,
            displayed_body=displayed_body,
            mutations=mutations,
            expected_participant_decision=expected_decision,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_study_trial", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )
    return Response(
        content=json.dumps(
            {
                "status": "pending",
                "study_run_id": study_run_id,
                "trial_id": trial_id,
                "intent_id": intent_id,
                "approval_url": f"/dashboard?poia_intent={intent_id}",
                "signing_backend": backend,
                "task": task_body,
                "displayed_intent_sha256": canonical_sha256(displayed_body),
                "original_request_sha256": canonical_sha256(original_body),
                "expected_participant_decision": expected_decision,
            }
        ),
        media_type="application/json",
        status_code=201,
    )


@router.get("/api/poia/experiment/human-study/status")
def api_poia_human_study_status(trial_id: str, request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied", "reason": "unauthorized"}), media_type="application/json", status_code=401)
    trial = load_trial(str(trial_id or ""))
    if trial is None:
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_trial"}), media_type="application/json", status_code=404)
    intent_record = poia_store.intents.get(str(trial["intent_id"]))
    if intent_record is None or intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return Response(content=json.dumps({"status": "denied", "reason": "principal_mismatch"}), media_type="application/json", status_code=403)
    proof = poia_store.proofs.get(str(trial["intent_id"]))
    proof_status = proof.status if proof is not None else "pending"
    challenge = poia_store.challenges.get(str(trial["intent_id"]))
    if (
        proof_status == "pending"
        and challenge is not None
        and int(time.time()) > int(challenge.expires_at)
    ):
        proof_status = "expired"
    return Response(
        content=json.dumps(
            {
                "status": "ok",
                "trial_id": trial["trial_id"],
                "signing_backend": trial["signing_backend"],
                "mutation_stage": trial["mutation_stage"],
                "participant_decision": trial["participant_decision"],
                "system_decision": trial["system_decision"],
                "rejection_reason": trial["rejection_reason"],
                "decision_time_ms": trial["decision_time_ms"],
                "proof_status": proof_status,
            }
        ),
        media_type="application/json",
    )


@router.post("/api/poia/experiment/human-study/execute")
@atomic_execution
def api_poia_human_study_execute(payload: dict, request: Request) -> Response:
    """Submit an exact or mutated operation through the live semantic gate."""
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied", "reason": "unauthorized"}), media_type="application/json", status_code=401)
    trial_id = str(payload.get("trial_id") or "")
    supplied_variant = str(payload.get("variant") or "")
    trial = load_trial(trial_id)
    if trial is None:
        return Response(content=json.dumps({"status": "denied", "reason": "invalid_trial"}), media_type="application/json", status_code=404)
    variant = "mutated" if trial["mutation_stage"] == "post_signature" else "exact"
    # This anti-relabeling check must hold in every environment, test mode
    # included -- it is what stops a participant/experimenter from resubmitting
    # a trial under a variant label that does not match how the trial was
    # created (see tests/test_human_study_http.py), which matters for the
    # integrity of the human-study telemetry this data feeds into the paper.
    if supplied_variant and supplied_variant != variant:
        return Response(
            content=json.dumps({"status": "denied", "reason": "execution_variant_mismatch"}),
            media_type="application/json",
            status_code=400,
        )
    intent_record = poia_store.intents.get(str(trial["intent_id"]))
    challenge = poia_store.challenges.get(str(trial["intent_id"]))
    if intent_record is None or challenge is None:
        return Response(content=json.dumps({"status": "denied", "reason": "intent_invalid"}), media_type="application/json", status_code=404)
    if intent_record.intent_body.get("context", {}).get("user_id") != user["id"]:
        return Response(content=json.dumps({"status": "denied", "reason": "principal_mismatch"}), media_type="application/json", status_code=403)
    displayed_body = json.loads(trial["displayed_body"])
    mutations = json.loads(trial["mutation_spec"])
    requested = canonical_copy(displayed_body)
    if variant == "mutated":
        requested = apply_mutations(requested, mutations)
    requested_action = str(requested.get("action") or "")
    try:
        validate_study_operation(requested_action, requested.get("scope", {}))
    except (TypeError, ValueError) as exc:
        return Response(
            content=json.dumps({"status": "denied", "reason": "invalid_execution", "detail": str(exc)}),
            media_type="application/json",
            status_code=400,
        )
    before = track_a_recorder.capture_state(user["id"], str(requested.get("action")), requested.get("scope", {}))
    binding_reason = original_request_binding_reason(intent_record)
    if binding_reason:
        accepted, reason = False, binding_reason
    else:
        accepted, reason, _, _ = poia_store.reserve_execution(
            intent_record.intent_id, user["id"], time.time(), requested
        )
    if accepted and requested_action == "transfer":
        response = execute_transfer(request, user, intent_record.intent_body)
        rejection_reason = response.headers.get("X-PoIA-Rejection-Reason")
        decision = "reject" if rejection_reason else "accept"
    elif accepted and requested_action == "beneficiary_add":
        execute_beneficiary_add(request, user, requested)
        decision, rejection_reason = "accept", None
    elif accepted and requested_action == "withdrawal":
        execute_cash(request, user, requested)
        decision, rejection_reason = "accept", None
    elif accepted and requested_action == "statement_export":
        execute_statements_export(request, user, requested)
        with db_connect() as conn:
            conn.execute(
                "INSERT INTO experiment_api_operations (user_id, action, object_id, created_at) "
                "VALUES (?, 'statement_export', ?, ?)",
                (
                    user["id"],
                    canonical_sha256(requested.get("scope", {})),
                    int(time.time()),
                ),
            )
        decision, rejection_reason = "accept", None
    elif accepted and requested_action.startswith("cloud_file_"):
        cloud_accepted, cloud_reason = execute_cloud_study_action(
            user["id"], requested_action, requested.get("scope", {})
        )
        decision = "accept" if cloud_accepted else "reject"
        rejection_reason = cloud_reason
    elif accepted:
        decision, rejection_reason = "reject", "unsupported_study_action"
    else:
        decision, rejection_reason = "reject", reason
    after = track_a_recorder.capture_state(user["id"], str(requested.get("action")), requested.get("scope", {}))
    proof = poia_store.proofs.get(str(trial["intent_id"]))
    proof_status = proof.status if proof is not None else "missing"
    append_system_event(
        trial_id=trial_id,
        event_type=f"execution_{variant}",
        execution_body=requested,
        decision=decision,
        rejection_reason=rejection_reason,
        proof_status=proof_status,
        state_before_sha256=before.get("digest"),
        state_after_sha256=after.get("digest"),
    )
    record_system_decision(
        trial_id,
        requested,
        decision,
        rejection_reason,
        proof_status=proof_status,
    )
    return Response(
        content=json.dumps(
            {
                "status": decision,
                "reason": rejection_reason,
                "trial_id": trial_id,
                "variant": variant,
                "original_request_sha256": trial["original_sha256"],
                "displayed_intent_sha256": trial["displayed_sha256"],
                "execution_sha256": canonical_sha256(requested),
                "state_before_sha256": before.get("digest"),
                "state_after_sha256": after.get("digest"),
                "state_changed": before.get("digest") != after.get("digest"),
            }
        ),
        media_type="application/json",
        status_code=200 if decision == "accept" else 409,
    )


@router.post("/api/poia/experiment/human-study/cloud/reset")
def api_poia_human_study_cloud_reset(request: Request) -> Response:
    if not POIA_EXPERIMENT_MODE:
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json", status_code=403)
    user = get_current_user(request)
    if not require_login(user):
        return Response(content=json.dumps({"status": "denied", "reason": "unauthorized"}), media_type="application/json", status_code=401)
    reset_cloud_resources(user["id"])
    return Response(
        content=json.dumps({"status": "reset", "resources": list_cloud_resources(user["id"])}),
        media_type="application/json",
    )


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
                "token_type": "Bearer",  # nosec B105
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
@atomic_execution
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
def api_poia_pending(
    user_id: int,
    request: Request,
    force: int = 0,
    device_id: int | None = None,
    rp_id: str = "",
) -> Response:
    session_user = get_current_user(request)
    browser_owner = bool(session_user and session_user["id"] == user_id)
    if not browser_owner:
        from ..security import authenticate_device_poll
        if device_id is None or not authenticate_device_poll(request, user_id, device_id, rp_id):
            return Response(content=json.dumps({"status": "denied", "reason": "device_auth_required"}),
                            media_type="application/json", status_code=401)
    with db_connect() as conn:
        user = conn.execute("SELECT poia_zt_enabled FROM users WHERE id = ?", (user_id,)).fetchone()
        if not browser_owner:
            if device_id is None or not rp_id:
                return Response(
                    content=json.dumps({"status": "none", "reason": "device_required"}),
                    media_type="application/json",
                    status_code=403,
                )
            device_key = conn.execute(
                """
                SELECT device_keys.id
                FROM device_keys
                JOIN devices ON devices.id = device_keys.device_id
                WHERE devices.user_id = ?
                  AND device_keys.device_id = ?
                  AND device_keys.rp_id = ?
                LIMIT 1
                """,
                (user_id, device_id, rp_id),
            ).fetchone()
            if not device_key:
                return Response(
                    content=json.dumps({"status": "none", "reason": "device_not_enrolled"}),
                    media_type="application/json",
                )
    if not user or (not user["poia_zt_enabled"] and not (force and POIA_TEST_MODE)):
        return Response(content=json.dumps({"status": "disabled"}), media_type="application/json")
    now = int(time.time())
    # Only an unexpired challenge can yield a servable intent, and those are a
    # small fraction of the durable store. Selecting them in SQL and then bulk
    # loading just those records replaces a per-record query storm -- three
    # round trips for every intent ever created, on every poll -- with four
    # queries. active_ids() orders by record_id, the same order __iter__
    # yielded from the primary-key index, so the record chosen below is the
    # one that would have been chosen before. Filters are unchanged.
    active_ids = poia_store.challenges.active_ids("$.expires_at", now)
    active_challenges = poia_store.challenges.fetch_many(active_ids)
    active_intents = poia_store.intents.fetch_many(active_ids)
    active_proofs = poia_store.proofs.fetch_many(active_ids)
    pending = []
    for intent_id in active_ids:
        intent_record = active_intents.get(intent_id)
        challenge = active_challenges.get(intent_id)
        proof = active_proofs.get(intent_id)
        if not challenge or not intent_record:
            continue
        if int(challenge.expires_at) <= now:
            continue
        if intent_record.intent_body.get("context", {}).get("user_id") != user_id:
            continue
        study_backend = _study_backend_for_intent(intent_id)
        if study_backend and study_backend != "zt_authenticator":
            continue
        if proof and proof.status != "pending":
            continue
        pending.append(intent_id)
    if not pending:
        return Response(content=json.dumps({"status": "none"}), media_type="application/json")
    # Re-read the served records through the normal path so they keep their
    # persistence callback, exactly as before this bulk-read optimization.
    intent_id = pending[0]
    intent_record = poia_store.intents[intent_id]
    challenge = poia_store.challenges[intent_id]
    record_prompt_displayed(intent_id)
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
    signing_rp = _signing_rp_for_intent(intent_id, intent_record)
    payload = {
        "status": "pending",
        "intent_id": intent_id,
        "intent": intent_record.intent_body,
        "display_fields": render_intent_fields(
            intent_record.intent_body.get("action", ""),
            intent_record.intent_body.get("scope", {}),
            intent_record.intent_body.get("context", {}),
        ),
        "scope_display_overrides": resolve_scope_display_overrides(
            intent_record.intent_body.get("scope", {})
        ),
        "nonce": challenge.nonce,
        "rp_id": signing_rp,
        "intent_hash": proof_hash,
        "intent_body_hash": body_hash,
        "intent_canonical_json": canonical_json(intent_record.intent_body).decode("utf-8"),
        "proof_payload_json": proof_payload.decode("utf-8"),
        "expires_at": int(challenge.expires_at),
        "expires_in": max(0, int(challenge.expires_at) - now),
        "display_variant": _display_variant_for_intent(intent_id),
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
    submitted_hash = (payload.get("intent_hash") or "").strip()
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_fields"}), media_type="application/json", status_code=400)

    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    if not intent_record or not challenge:
        return Response(content=json.dumps({"status": "denied", "reason": "intent_invalid"}), media_type="application/json", status_code=404)

    study_backend = _study_backend_for_intent(intent_id)
    if study_backend and study_backend != "zt_authenticator":
        return Response(
            content=json.dumps({"status": "denied", "reason": "wrong_signing_backend"}),
            media_type="application/json",
            status_code=409,
        )

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

    if not device_id_raw or not rp_id or not nonce or not signature or not submitted_hash:
        return deny("missing_fields")
    try:
        device_id = int(device_id_raw)
    except (TypeError, ValueError):
        return deny("invalid_device")
    proof = poia_store.proofs.get(intent_id)
    if proof and proof.status != "pending":
        return deny("replay", 409)
    signing_rp = _signing_rp_for_intent(intent_id, intent_record)
    if signing_rp != rp_id:
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
    if not secrets.compare_digest(submitted_hash, proof_hash):
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
    approval_message = f"{nonce}|{device_id}|{rp_id}|poia-approve:{proof_hash}".encode("utf-8")

    from ..db import db_connect

    with db_connect() as conn:
        device_key = conn.execute(
            "SELECT device_keys.* FROM device_keys "
            "JOIN devices ON devices.id = device_keys.device_id "
            "WHERE device_keys.device_id = ? AND device_keys.rp_id = ? "
            "AND devices.user_id = ? ORDER BY device_keys.created_at DESC LIMIT 1",
            (device_id, rp_id, intent_record.intent_body.get("context", {}).get("user_id")),
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
    if not verify_p256_signature(device_key["public_key"], approval_message, signature):
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

    binding_reason = original_request_binding_reason(intent_record)
    if binding_reason and _spontaneous_trial_for_intent(intent_id) is None:
        record_participant_decision(
            intent_id,
            "sign",
            system_decision="reject",
            rejection_reason=binding_reason,
        )
        log_poia_event(
            event="intent_approve",
            intent_id=intent_id,
            user_id=intent_record.intent_body.get("context", {}).get("user_id"),
            rp_id=rp_id,
            action=intent_record.intent_body.get("action"),
            status="denied",
            reason=binding_reason,
            created_at=intent_record.created_at,
            expires_at=challenge.expires_at,
            method="zt_authenticator",
        )
        return deny(binding_reason, 409)

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
    record_participant_decision(
        intent_id,
        "sign",
        system_decision="approved",
        proof_status="approved",
    )
    return Response(content=json.dumps({"status": "ok"}), media_type="application/json")


@router.post("/api/poia/deny")
def api_poia_deny(payload: dict, request: Request) -> Response:
    started_ns = time.perf_counter_ns()
    intent_id = payload.get("intent_id") or payload.get("intentId") or payload.get("id")
    if not intent_id:
        return Response(content=json.dumps({"status": "denied", "reason": "missing_intent"}), media_type="application/json", status_code=400)
    intent_record = poia_store.intents.get(intent_id)
    challenge = poia_store.challenges.get(intent_id)
    proof = poia_store.proofs.get(intent_id)
    if intent_record is None or challenge is None or proof is None:
        return Response(
            content=json.dumps({"status": "denied", "reason": "intent_invalid"}),
            media_type="application/json",
            status_code=404,
        )
    if proof.status != "pending":
        return Response(
            content=json.dumps({"status": "denied", "reason": "intent_not_pending"}),
            media_type="application/json",
            status_code=409,
        )

    owner_id = intent_record.intent_body.get("context", {}).get("user_id")
    session_user = get_current_user(request)
    browser_owner = bool(session_user and session_user["id"] == owner_id)
    method = "browser"
    if not browser_owner:
        device_id_raw = payload.get("device_id")
        rp_id = str(payload.get("rp_id") or "").strip()
        nonce = str(payload.get("nonce") or "").strip()
        signature = str(payload.get("signature") or "").strip()
        submitted_hash = str(payload.get("intent_hash") or "").strip()
        if not device_id_raw or not rp_id or not nonce or not signature or not submitted_hash:
            return Response(
                content=json.dumps({"status": "denied", "reason": "device_proof_required"}),
                media_type="application/json",
                status_code=401,
            )
        try:
            device_id = int(device_id_raw)
        except (TypeError, ValueError):
            return Response(
                content=json.dumps({"status": "denied", "reason": "invalid_device"}),
                media_type="application/json",
                status_code=400,
            )
        expected_rp = _signing_rp_for_intent(str(intent_id), intent_record)
        if rp_id != expected_rp or nonce_mismatch_reason(challenge, nonce):
            return Response(
                content=json.dumps({"status": "denied", "reason": "challenge_mismatch"}),
                media_type="application/json",
                status_code=400,
            )
        proof_hash = hashlib.sha256(
            build_proof_payload(intent_record.intent_body, challenge.nonce, challenge.expires_at)
        ).hexdigest()
        if not secrets.compare_digest(submitted_hash, proof_hash):
            return Response(
                content=json.dumps({"status": "denied", "reason": "hash_mismatch"}),
                media_type="application/json",
                status_code=400,
            )
        with db_connect() as conn:
            device_key = conn.execute(
                "SELECT device_keys.* FROM device_keys "
                "JOIN devices ON devices.id = device_keys.device_id "
                "WHERE device_keys.device_id = ? AND device_keys.rp_id = ? "
                "AND devices.user_id = ? ORDER BY device_keys.created_at DESC LIMIT 1",
                (device_id, rp_id, owner_id),
            ).fetchone()
        from ..security import verify_p256_signature

        denial_message = f"{nonce}|{device_id}|{rp_id}|poia-deny:{proof_hash}".encode("utf-8")
        if (
            not device_key
            or device_key["key_type"] != "p256"
            or not verify_p256_signature(device_key["public_key"], denial_message, signature)
        ):
            return Response(
                content=json.dumps({"status": "denied", "reason": "invalid_device_proof"}),
                media_type="application/json",
                status_code=401,
            )
        method = "zt_authenticator"

    reason = str(payload.get("reason") or "user_denied")
    if reason not in {"user_denied", "user_cancelled", "expired"}:
        reason = "user_denied"
    expired = time.time() >= challenge.expires_at
    if reason == "expired" and not expired:
        return _participant_json({"status": "not_expired"}, 409)
    if expired:
        reason = "expired"
    proof.status = "denied"
    proof.message = "Denied"
    if expired:
        with db_connect() as conn:
            conn.execute(
                "UPDATE poia_human_study_trials SET system_decision = 'expired', "
                "rejection_reason = 'expired', proof_status = 'expired' "
                "WHERE intent_id = ? AND participant_decision IS NULL", (intent_id,),
            )
    else:
        record_participant_decision(
            intent_id, "refuse", system_decision="user_refused", proof_status="denied",
        )
    log_poia_event(
        event="intent_deny",
        intent_id=intent_id,
        user_id=owner_id,
        rp_id=intent_record.intent_body.get("context", {}).get("rp_id"),
        action=intent_record.intent_body.get("action"),
        status="denied",
        reason=reason,
        created_at=intent_record.created_at,
        expires_at=challenge.expires_at,
        method=method,
    )
    log_audit(
        owner_id,
        "poia_deny",
        f"Intent {intent_id} denied",
    )
    response = Response(content=json.dumps({"status": "denied"}), media_type="application/json")
    track_a_recorder.record_rejection(
        request=request,
        intent_id=intent_id,
        intent_body=intent_record.intent_body,
        nonce=challenge.nonce,
        rejection_reason=reason,
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
    binding_reason = original_request_binding_reason(intent_record)
    if binding_reason:
        return Response(
            content=json.dumps({"status": "denied", "reason": binding_reason}),
            media_type="application/json",
            status_code=409,
        )
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
    if event == "intent_loaded" and intent_id:
        record_prompt_displayed(str(intent_id))
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
