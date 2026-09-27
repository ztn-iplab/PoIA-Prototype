import base64
import hashlib
import json
import secrets
import time
from contextlib import nullcontext
from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .commitment_confinement import confine_commitment
from .db import db_connect
from .intent_codec import build_intent, canonical_json
from .model import ChallengeRecord, IntentRecord, ProofRecord
from .durable_poia import DurablePoIA
from .db import transaction
from .poia_metrics import log_poia_event
from .settings import (
    BASE_DIR,
    INTENT_TTL_SECONDS,
    POIA_ENABLED,
    RSI_ENABLED,
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# An earlier prototype iteration verified proofs against a single, server-held
# Ed25519 keypair (a simulated software signer) before the WebAuthn and
# ZT-Authenticator hardware-backed realizations in Section VI replaced it. That
# demo-mode class, its module-level instance, and the verify_proof() function
# below that was its only caller have been removed: they were confirmed dead
# (zero callers, zero test coverage) and, being a single shared signing key
# rather than a per-user enrolled credential, did not represent a realization
# this paper claims or evaluates -- leaving unreachable code implementing a
# weaker, unclaimed verification path in a security-critical module is a
# liability for review and reproducibility, not a harmless fallback.
poia_store = DurablePoIA()


def static_asset_version(filename: str) -> str:
    """Cache-busting token for a file under app/static, derived from its own
    mtime so a stylesheet edit always produces a new URL. A previous version
    of base.html hardcoded "?v=2" on style.css's <link> tag; that literal
    never changed across many later edits to the file, so browsers kept
    serving an already-cached copy of the *old* stylesheet indefinitely --
    invisible in this dev server (uvicorn --reload only watches .py files,
    and each direct curl/test request bypasses any browser cache), but very
    visible to anyone actually using the site in a browser across sessions.
    Falling back to "0" if the file is briefly missing avoids a 500 on a
    template render mid-deploy.
    """
    try:
        return str(int((BASE_DIR / "static" / filename).stat().st_mtime))
    except OSError:
        return "0"


def render(request: Request, template_name: str, context: Optional[Dict[str, Any]] = None) -> HTMLResponse:
    user = get_current_user(request)
    base_context = {
        "request": request,
        "user": user,
        "user_id": user["id"] if user else None,
        "flash_message": request.session.pop("flash_message", ""),
        "poia_intent_id": request.query_params.get("poia_intent", ""),
        "static_version": static_asset_version("style.css"),
        # Confirmation-modal layout for the sign-intent overlay. Every real
        # banking page renders "redesigned" (today's grouped/avatar layout);
        # only the participant-study route overrides this per-session, to
        # the participant's assigned display_variant arm (see
        # app/human_study.py DISPLAY_VARIANTS).
        "display_variant": "redesigned",
    }
    if context:
        base_context.update(context)
    response = templates.TemplateResponse(request, template_name, base_context)
    if context and context.get("status") == "Rejected":
        response.status_code = 409
        response.headers["X-PoIA-Rejection-Reason"] = "operation_rejected"
    return response


def get_current_user(request: Request) -> Optional[Any]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with db_connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is not None and user["disabled"]:
        # An admin-disabled account loses its session immediately, not just
        # at next login -- this is the single point every route's
        # get_current_user()/require_login() check flows through.
        request.session.clear()
        return None
    return user


def require_login(user: Optional[Any]) -> bool:
    return user is not None


def intent_hash(intent_body: Dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(intent_body)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def canonical_sha256(intent_body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(intent_body)).hexdigest()


def original_request_binding_reason(intent_record: IntentRecord) -> Optional[str]:
    """Validate the append-only order that the displayed intent was derived from."""
    if not intent_record.original_request_id or not intent_record.original_request_hash:
        return "original_request_missing"
    with db_connect() as conn:
        original = conn.execute(
            "SELECT canonical_body, canonical_sha256, intent_id "
            "FROM poia_original_requests WHERE request_id = ?",
            (intent_record.original_request_id,),
        ).fetchone()
    if original is None or original["intent_id"] != intent_record.intent_id:
        return "original_request_missing"
    try:
        original_body = json.loads(original["canonical_body"])
    except (TypeError, ValueError):
        return "original_request_integrity_error"
    stored_hash = canonical_sha256(original_body)
    if (
        stored_hash != original["canonical_sha256"]
        or stored_hash != intent_record.original_request_hash
    ):
        return "original_request_integrity_error"
    if canonical_json(original_body) != canonical_json(intent_record.intent_body):
        return "original_request_mismatch"
    return None


def build_proof_payload(intent_body: Dict[str, Any], nonce: str, expires_at: float) -> bytes:
    payload = {
        "intent_hash": intent_hash(intent_body),
        "nonce": nonce,
        "expires_at": int(expires_at),
    }
    return canonical_json(payload)



def poia_required(action: str, amount: float = 0.0) -> bool:
    if not POIA_ENABLED:
        return False
    return action in {
        "transfer",
        "withdrawal",
        "deposit",
        "beneficiary_add",
        "beneficiary_edit",
        "limit_change",
        "account_recovery",
        "statement_export",
        "cloud_file_view",
        "cloud_file_download",
        "cloud_file_delete",
        "cloud_file_share_public",
        "cloud_file_overwrite",
        "admin_audit_view",
        "admin_mfa_view",
    }


class PoIACommitmentError(Exception):
    """Raised when k-of-n Independent Commitment Confinement refuses to commit an
    intent because its independent roots disagree on the content being authorized.
    This should fire only on a genuine bug or an active compromise attempt; every
    ordinary request is expected to pass through silently."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def beneficiary_row_content_hash(row: Any) -> str:
    """Content hash for a beneficiary's current bank-transfer-relevant fields.
    This is the referent Referent-State Integrity commits to at signing time and
    re-verifies immediately before execution (Section V, formal-models/referent_state_integrity.spthy)."""
    payload = {
        "name": row["name"],
        "bank": row["bank"],
        "account_number": row["account_number"],
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def account_row_content_hash(row: Any) -> str:
    """Content hash for the account fields that `limit_change` and `account_recovery`
    intents refer to (status, current daily transfer limit). Same role as
    `beneficiary_row_content_hash`, for the account referent type."""
    payload = {
        "status": row["status"],
        "daily_transfer_limit": row["daily_transfer_limit"],
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def compute_referent_commitments(action: str, scope: Dict[str, Any]) -> list:
    """Snapshot the live content of anything this intent references by ID, so
    execution can later re-verify it hasn't changed underneath the signed intent
    (Referent-State Integrity). Returns an empty list for actions with no mutable
    referent -- those are simply not exposed to a referent-substitution attack."""
    commitments: list = []
    if action == "transfer":
        beneficiary_id = scope.get("beneficiary_id")
        if beneficiary_id:
            with db_connect() as conn:
                beneficiary = conn.execute(
                    "SELECT * FROM beneficiaries WHERE id = ?", (beneficiary_id,)
                ).fetchone()
            if beneficiary is not None:
                commitments.append(
                    {
                        "type": "beneficiary",
                        "id": beneficiary_id,
                        "version": beneficiary["version"],
                        "content_sha256": beneficiary_row_content_hash(beneficiary),
                        "content": {key: beneficiary[key] for key in ("name", "bank", "account_number")},
                    }
                )
    elif action in {"limit_change", "account_recovery"}:
        account_id = scope.get("account_id")
        if account_id:
            with db_connect() as conn:
                account = conn.execute(
                    "SELECT * FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
            if account is not None:
                commitments.append(
                    {
                        "type": "account",
                        "id": account_id,
                        "version": account["version"],
                        "content_sha256": account_row_content_hash(account),
                        "content": {key: account[key] for key in ("status", "daily_transfer_limit")},
                    }
                )
    return commitments


def verify_referent_commitments(intent_body: Dict[str, Any], *, conn=None) -> Optional[str]:
    """Referent-State Integrity execution gate (D_RSI). Re-reads every referent this
    intent committed to at signing time and requires its content hash to still match.
    Returns None (accept) if RSI is disabled, there is nothing to check, or every
    referent still matches; otherwise a rejection reason string. Rejecting here must
    leave application state untouched, exactly like every other PoIA rejection."""
    if not RSI_ENABLED:
        return None
    commitments = (intent_body.get("context", {}) or {}).get("referent_commitments") or []
    scope = intent_body.get("scope", {})
    action = intent_body.get("action")
    expected = []
    if action == "transfer" and scope.get("beneficiary_id"):
        expected = [("beneficiary", scope["beneficiary_id"])]
    elif action in {"limit_change", "account_recovery"}:
        expected = [("account", scope.get("account_id"))]
    if not isinstance(commitments, list) or any(not isinstance(item, dict) for item in commitments):
        return "referent_commitment_invalid"
    if [(item.get("type"), item.get("id")) for item in commitments] != expected:
        return "referent_commitment_missing_or_unexpected"
    for commitment in commitments:
        referent_type = commitment.get("type")
        if referent_type == "beneficiary":
            with (nullcontext(conn) if conn is not None else db_connect()) as reader:
                beneficiary = reader.execute(
                    "SELECT * FROM beneficiaries WHERE id = ?", (commitment.get("id"),)
                ).fetchone()
            if beneficiary is None:
                return "referent_state_missing"
            if beneficiary["version"] != commitment.get("version"):
                return "referent_version_mismatch"
            current_hash = beneficiary_row_content_hash(beneficiary)
            if not secrets.compare_digest(current_hash, str(commitment.get("content_sha256", ""))):
                return "referent_state_mismatch"
        elif referent_type == "account":
            with (nullcontext(conn) if conn is not None else db_connect()) as reader:
                account = reader.execute(
                    "SELECT * FROM accounts WHERE id = ?", (commitment.get("id"),)
                ).fetchone()
            if account is None:
                return "referent_state_missing"
            if account["version"] != commitment.get("version"):
                return "referent_version_mismatch"
            current_hash = account_row_content_hash(account)
            if not secrets.compare_digest(current_hash, str(commitment.get("content_sha256", ""))):
                return "referent_state_mismatch"
    return None


@transaction()
def create_poia_intent(
    *,
    action: str,
    scope: Dict[str, Any],
    context: Dict[str, Any],
    original_request_body: Optional[Dict[str, Any]] = None,
    original_request_id: Optional[str] = None,
) -> str:
    # k-of-n Independent Commitment Confinement (D_Kk): refuse to commit rather than
    # sign whatever a single component reports, if the independent roots disagree.
    confinement_reason = confine_commitment(action=action, scope=scope, context=context)
    if confinement_reason:
        log_audit(
            context.get("user_id") if isinstance(context, dict) else None,
            "commitment_confinement_refused",
            f"action={action} reason={confinement_reason}",
        )
        raise PoIACommitmentError(confinement_reason)

    # Referent-State Integrity (D_RSI): snapshot the live content of anything this
    # intent references by ID now, so execution can re-verify it later.
    context = dict(context)
    referent_commitments = compute_referent_commitments(action, scope)
    if referent_commitments:
        context["referent_commitments"] = referent_commitments

    intent_id = secrets.token_urlsafe(12)
    intent_body = json.loads(
        canonical_json(
            build_intent(
                action=action,
                scope=scope,
                context=context,
                ttl_seconds=INTENT_TTL_SECONDS,
            )
        )
    )
    original_body = json.loads(
        canonical_json(original_request_body or intent_body)
    )
    request_id = original_request_id or secrets.token_urlsafe(12)
    original_hash = canonical_sha256(original_body)
    original_context = original_body.get("context", {})
    original_user_id = original_context.get("user_id")
    original_rp_id = original_context.get("rp_id")
    if not isinstance(original_user_id, int) or not isinstance(original_rp_id, str):
        raise ValueError("original request requires integer user_id and string rp_id")
    created_at = time.time()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO poia_original_requests "
            "(request_id, intent_id, user_id, rp_id, canonical_body, canonical_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                request_id,
                intent_id,
                original_user_id,
                original_rp_id,
                canonical_json(original_body).decode("utf-8"),
                original_hash,
                created_at,
            ),
        )
    poia_store.intents[intent_id] = IntentRecord(
        intent_id=intent_id,
        intent_body=intent_body,
        created_at=created_at,
        original_request_id=request_id,
        original_request_hash=original_hash,
    )
    poia_store.proofs[intent_id] = ProofRecord(
        intent_id=intent_id,
        signature_b64="",
        status="pending",
        message="Pending",
        latency_ms=0,
    )
    nonce = secrets.token_urlsafe(16)
    expires_at = time.time() + INTENT_TTL_SECONDS
    poia_store.challenges[intent_id] = ChallengeRecord(
        intent_id=intent_id,
        nonce=nonce,
        expires_at=expires_at,
    )
    user_id = context.get("user_id") if isinstance(context, dict) else None
    rp_id = context.get("rp_id") if isinstance(context, dict) else None
    log_poia_event(
        event="intent_created",
        intent_id=intent_id,
        user_id=user_id,
        rp_id=rp_id,
        action=action,
        status="pending",
        created_at=poia_store.intents[intent_id].created_at,
        expires_at=expires_at,
        payload={"scope": scope},
    )
    return intent_id


def log_audit(user_id: Optional[int], action: str, details: str) -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (user_id, action, details, int(time.time())),
        )


def log_mfa_event(user_id: Optional[int], status: str, reason: Optional[str], duration_ms: Optional[int]) -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO mfa_events (user_id, status, reason, duration_ms, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, status, reason, duration_ms, int(time.time())),
        )
