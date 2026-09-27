from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sign_service_request(secret: str, timestamp: str, body: Mapping[str, Any]) -> str:
    message = timestamp.encode("ascii") + b"." + canonical_json(body)
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_service_request(
    secret: str, timestamp: str, body: Mapping[str, Any], signature: str
) -> bool:
    expected = sign_service_request(secret, timestamp, body)
    return hmac.compare_digest(expected, signature)


def sign_attestation(secret: str, claims: Mapping[str, Any]) -> str:
    return hmac.new(
        secret.encode("utf-8"), canonical_json(claims), hashlib.sha256
    ).hexdigest()


def verify_attestation(secret: str, claims: Mapping[str, Any], signature: str) -> bool:
    return hmac.compare_digest(sign_attestation(secret, claims), signature)
