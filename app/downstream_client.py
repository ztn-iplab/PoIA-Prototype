from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import hashlib
from typing import Any, Dict, Mapping, Tuple

from downstream.security import sign_attestation, sign_service_request

from .core import intent_hash


class DownstreamClient:
    MAX_RESPONSE_BYTES = 1024 * 1024

    def __init__(self) -> None:
        self.base_url = os.getenv("POIA_DOWNSTREAM_URL", "http://poia-ledger:8010").rstrip("/")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("POIA_DOWNSTREAM_URL must be an HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("POIA_DOWNSTREAM_URL must not contain credentials")
        self.service_id = os.getenv("POIA_DOWNSTREAM_SERVICE_ID", "poia-bank")
        self.secret = os.getenv("POIA_DOWNSTREAM_SECRET", "")
        self.timeout = float(os.getenv("POIA_DOWNSTREAM_TIMEOUT_SECONDS", "5"))

    @classmethod
    def _decode_response(cls, stream: Any) -> Dict[str, Any] | None:
        raw = stream.read(cls.MAX_RESPONSE_BYTES + 1)
        if len(raw) > cls.MAX_RESPONSE_BYTES:
            return None
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, dict) else None

    def _post(self, path: str, body: Mapping[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not self.secret:
            return 503, {"status": "denied", "reason": "service_not_configured"}
        timestamp = str(int(time.time()))
        signature = sign_service_request(self.secret, timestamp, body)
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-PoIA-Service-Id": self.service_id,
                "X-PoIA-Service-Timestamp": timestamp,
                "X-PoIA-Service-Signature": signature,
            },
        )
        try:
            # base_url is restricted to credential-free HTTP(S) in __init__.
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
                body = self._decode_response(response)
                if body is None:
                    return 503, {"status": "denied", "reason": "invalid_downstream_response"}
                return response.status, body
        except urllib.error.HTTPError as exc:
            body = self._decode_response(exc)
            return (
                (exc.code, body)
                if body is not None
                else (503, {"status": "denied", "reason": "invalid_downstream_response"})
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return 503, {"status": "denied", "reason": "downstream_unavailable"}

    def state(self, principal: str) -> Dict[str, Any]:
        status, body = self._post("/ledger/state", {"principal": principal})
        if status != 200:
            return {"available": False, "reason": body.get("reason", "state_unavailable")}
        return {"available": True, **body["state"]}

    def post_ledger_entry(
        self, intent_body: Mapping[str, Any], proof_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        request_id = hashlib.sha256(f"poia-ledger:{proof_id}".encode()).hexdigest()
        claims = {
            "request_id": request_id,
            "action": intent_body.get("action"),
            "scope": intent_body.get("scope", {}),
            "context": intent_body.get("context", {}),
            "intent_hash": intent_hash(dict(intent_body)),
            "proof_id": proof_id,
        }
        body = {
            "request_id": request_id,
            "action": claims["action"],
            "scope": claims["scope"],
            "context": claims["context"],
            "poia_attestation": {
                "claims": claims,
                "signature": sign_attestation(self.secret, claims),
            },
        }
        return self._post("/ledger/entries", body)


downstream_client = DownstreamClient()
