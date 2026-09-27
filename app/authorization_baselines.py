"""Executable authorization gates for the Track B comparative baselines."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .intent_codec import canonical_json


Decision = Tuple[bool, Optional[str]]


@dataclass(frozen=True)
class AuthorizationRequest:
    principal: str
    action: str
    scope: Dict[str, Any]
    context: Dict[str, Any]

    def intent(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "scope": self.scope,
            "context": {**self.context, "user_id": self.principal},
            "constraints": {"expires_in_seconds": 60},
        }


class SessionOnlyGate:
    def authorize(self, request: AuthorizationRequest, now: float) -> Decision:
        del request, now
        return True, None


class MFAConfirmationGate:
    """Confirms recent user presence without binding operation semantics."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._approvals: Dict[str, float] = {}

    def approve(self, principal: str, now: float) -> None:
        self._approvals[principal] = now + self.ttl_seconds

    def authorize(self, request: AuthorizationRequest, now: float) -> Decision:
        if self._approvals.get(request.principal, 0) < now:
            return False, "mfa_confirmation_missing_or_expired"
        return True, None


class TransactionConfirmationGate:
    """Binds a fixed banking field set, omitting context and workflow semantics."""

    def __init__(self) -> None:
        self._approval: Optional[tuple] = None
        self._consumed = False

    @staticmethod
    def displayed_fields(request: AuthorizationRequest) -> tuple:
        amount = json.dumps(request.scope.get("amount"), sort_keys=True)
        beneficiary = json.dumps({key: request.scope.get(key) for key in (
            "beneficiary_id", "external_account", "to_account", "target_object"
        )}, sort_keys=True)
        return request.principal, request.action, amount, request.scope.get("currency"), beneficiary

    def approve(self, request: AuthorizationRequest) -> None:
        self._approval = self.displayed_fields(request)
        self._consumed = False

    def authorize(self, request: AuthorizationRequest, now: float) -> Decision:
        del now
        if self._approval is None:
            return False, "transaction_confirmation_missing"
        if self._consumed:
            return False, "transaction_confirmation_consumed"
        if self.displayed_fields(request) != self._approval:
            return False, "displayed_field_mismatch"
        self._consumed = True
        return True, None


class PoIAExactIntentGate:
    def __init__(self) -> None:
        self._intent_hash: Optional[str] = None
        self._consumed = False

    def approve(self, request: AuthorizationRequest) -> None:
        self._intent_hash = hashlib.sha256(canonical_json(request.intent())).hexdigest()
        self._consumed = False

    def authorize(self, request: AuthorizationRequest, now: float) -> Decision:
        del now
        if self._intent_hash is None:
            return False, "proof_missing"
        if self._consumed:
            return False, "proof_consumed"
        requested_hash = hashlib.sha256(canonical_json(request.intent())).hexdigest()
        if requested_hash != self._intent_hash:
            return False, "semantic_mismatch"
        self._consumed = True
        return True, None
