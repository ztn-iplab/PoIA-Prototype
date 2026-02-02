import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .db import db_connect
from .model import ChallengeRecord, InMemoryPoIA, IntentRecord, ProofRecord
from .poia_metrics import log_poia_event
from .settings import (
    BASE_DIR,
    INTENT_TTL_SECONDS,
    POIA_ENABLED,
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class Authenticator:
    def __init__(self) -> None:
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)


authenticator = Authenticator()
poia_store = InMemoryPoIA()


def render(request: Request, template_name: str, context: Optional[Dict[str, Any]] = None) -> HTMLResponse:
    user = get_current_user(request)
    base_context = {
        "request": request,
        "user": user,
        "user_id": user["id"] if user else None,
        "flash_message": request.session.pop("flash_message", ""),
        "poia_intent_id": request.query_params.get("poia_intent", ""),
    }
    if context:
        base_context.update(context)
    return templates.TemplateResponse(template_name, base_context)


def get_current_user(request: Request) -> Optional[Any]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with db_connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def require_login(user: Optional[Any]) -> bool:
    return user is not None


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_intent(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": action,
        "scope": scope,
        "context": context,
        "constraints": {"expires_in_seconds": INTENT_TTL_SECONDS},
    }


def intent_hash(intent_body: Dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(intent_body)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def build_proof_payload(intent_body: Dict[str, Any], nonce: str, expires_at: float) -> bytes:
    payload = {
        "intent_hash": intent_hash(intent_body),
        "nonce": nonce,
        "expires_at": int(expires_at),
    }
    return canonical_json(payload)


def verify_proof(
    *,
    intent_body: Dict[str, Any],
    challenge: ChallengeRecord,
    proof: ProofRecord,
    requested_intent_body: Dict[str, Any],
) -> tuple[bool, str]:
    if int(time.time()) > int(challenge.expires_at):
        return False, "Intent expired"

    if canonical_json(intent_body) != canonical_json(requested_intent_body):
        return False, "Requested action does not match approved intent"

    payload = build_proof_payload(intent_body, challenge.nonce, challenge.expires_at)
    signature = base64.b64decode(proof.signature_b64.encode("ascii"))
    try:
        authenticator.public_key.verify(signature, payload)
    except Exception:
        return False, "Invalid signature"
    return True, "Approved"


def poia_required(action: str, amount: float = 0.0) -> bool:
    if not POIA_ENABLED:
        return False
    return action in {
        "transfer",
        "withdrawal",
        "deposit",
        "beneficiary_add",
        "statement_export",
        "admin_audit_view",
        "admin_mfa_view",
    }


def create_poia_intent(
    *,
    action: str,
    scope: Dict[str, Any],
    context: Dict[str, Any],
) -> str:
    intent_id = secrets.token_urlsafe(12)
    intent_body = build_intent(action=action, scope=scope, context=context)
    poia_store.intents[intent_id] = IntentRecord(
        intent_id=intent_id,
        intent_body=intent_body,
        created_at=time.time(),
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
