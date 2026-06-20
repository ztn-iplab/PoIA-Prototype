from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, Optional, Tuple

from .intent_codec import canonical_json


@dataclass
class IntentRecord:
    intent_id: str
    intent_body: Dict[str, Any]
    created_at: float


@dataclass
class ChallengeRecord:
    intent_id: str
    nonce: str
    expires_at: float


@dataclass
class ProofRecord:
    intent_id: str
    signature_b64: str
    status: str
    message: str
    latency_ms: int
    approved_at: Optional[float] = None
    consumed_at: Optional[float] = None


class InMemoryPoIA:
    def __init__(self) -> None:
        self.intents: Dict[str, IntentRecord] = {}
        self.challenges: Dict[str, ChallengeRecord] = {}
        self.proofs: Dict[str, ProofRecord] = {}
        self._lock = RLock()

    def approve_proof(self, proof: ProofRecord, now: float) -> Tuple[bool, str]:
        """Install a verified proof only while its challenge is fresh and pending."""
        with self._lock:
            challenge = self.challenges.get(proof.intent_id)
            current = self.proofs.get(proof.intent_id)
            if challenge is None or current is None:
                return False, "intent_invalid"
            if now > challenge.expires_at:
                return False, "expired"
            if current.status != "pending":
                return False, "replay"
            proof.status = "approved"
            proof.approved_at = now
            self.proofs[proof.intent_id] = proof
            return True, "approved"

    def reserve_execution(
        self,
        intent_id: str,
        principal_id: int,
        now: float,
        requested_intent_body: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Optional[IntentRecord], Optional[ChallengeRecord]]:
        """Atomically consume one approved proof before protected execution."""
        with self._lock:
            intent = self.intents.get(intent_id)
            challenge = self.challenges.get(intent_id)
            proof = self.proofs.get(intent_id)
            if intent is None or challenge is None:
                return False, "intent_invalid", intent, challenge
            if intent.intent_body.get("context", {}).get("user_id") != principal_id:
                return False, "principal_mismatch", intent, challenge
            if requested_intent_body is not None:
                mismatch = intent_mismatch_reason(
                    intent.intent_body, requested_intent_body
                )
                if mismatch is not None:
                    return False, mismatch, intent, challenge
            if proof is None:
                return False, "proof_missing", intent, challenge
            if proof.status == "consumed":
                return False, "proof_consumed", intent, challenge
            if proof.status != "approved":
                return False, "proof_not_approved", intent, challenge
            if now > challenge.expires_at:
                return False, "expired", intent, challenge
            proof.status = "consumed"
            proof.message = "Consumed"
            proof.consumed_at = now
            return True, "approved", intent, challenge


def intent_mismatch_reason(
    approved: Dict[str, Any], requested: Dict[str, Any]
) -> Optional[str]:
    """Return the most specific semantic mismatch without normalizing values."""
    if canonical_json({"value": approved.get("action")}) != canonical_json(
        {"value": requested.get("action")}
    ):
        return "action_mismatch"
    approved_context = approved.get("context", {})
    requested_context = requested.get("context", {})
    if canonical_json({"value": approved_context.get("workflow_id")}) != canonical_json(
        {"value": requested_context.get("workflow_id")}
    ):
        return "workflow_mismatch"
    if canonical_json({"value": approved_context.get("on_behalf_of")}) != canonical_json(
        {"value": requested_context.get("on_behalf_of")}
    ):
        return "delegation_mismatch"
    if canonical_json({"value": approved_context.get("user_id")}) != canonical_json(
        {"value": requested_context.get("user_id")}
    ):
        return "principal_mismatch"
    if canonical_json({"value": approved_context.get("rp_id")}) != canonical_json(
        {"value": requested_context.get("rp_id")}
    ):
        return "rp_mismatch"
    if canonical_json(approved_context) != canonical_json(requested_context):
        return "context_mismatch"
    if canonical_json(approved.get("scope", {})) != canonical_json(requested.get("scope", {})):
        return "scope_mismatch"
    if canonical_json(approved.get("constraints", {})) != canonical_json(
        requested.get("constraints", {})
    ):
        return "constraints_mismatch"
    if canonical_json(approved) != canonical_json(requested):
        return "intent_mismatch"
    return None
