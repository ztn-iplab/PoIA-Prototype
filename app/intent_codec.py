"""Deterministic PoIA intent normalization and canonical JSON encoding."""

from __future__ import annotations

import json
import math
import unicodedata
from typing import Any, Dict, Mapping


def normalize_intent_value(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("intent numbers must be finite")
        if value == 0:
            return 0
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, list):
        return [normalize_intent_value(item) for item in value]
    if isinstance(value, tuple):
        return [normalize_intent_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: Dict[str, Any] = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("intent object keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise ValueError("intent contains keys that collide after Unicode normalization")
            normalized[key] = normalize_intent_value(child)
        return normalized
    raise TypeError(f"unsupported intent value type: {type(value).__name__}")


def canonical_json(data: Mapping[str, Any]) -> bytes:
    normalized = normalize_intent_value(data)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def build_intent(
    action: str,
    scope: Dict[str, Any],
    context: Dict[str, Any],
    ttl_seconds: int = 60,
) -> Dict[str, Any]:
    return {
        "action": action,
        "scope": scope,
        "context": context,
        "constraints": {"expires_in_seconds": ttl_seconds},
    }
