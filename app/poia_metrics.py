import csv
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .settings import DATA_DIR

METRICS_CSV = DATA_DIR / "poia_experiments.csv"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _write_header_if_needed(path: Path, fieldnames: list[str]) -> None:
    if path.exists():
        return
    _ensure_parent(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()


def log_poia_event(
    *,
    event: str,
    intent_id: Optional[str] = None,
    user_id: Optional[int] = None,
    rp_id: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    reason: Optional[str] = None,
    method: Optional[str] = None,
    latency_ms: Optional[int] = None,
    created_at: Optional[float] = None,
    expires_at: Optional[float] = None,
    client_ts: Optional[float] = None,
    scenario: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    fieldnames = [
        "server_ts",
        "event",
        "intent_id",
        "user_id",
        "rp_id",
        "action",
        "status",
        "reason",
        "method",
        "latency_ms",
        "created_at",
        "expires_at",
        "client_ts",
        "scenario",
        "payload_json",
    ]
    _write_header_if_needed(METRICS_CSV, fieldnames)
    row = {
        "server_ts": int(time.time()),
        "event": event,
        "intent_id": intent_id or "",
        "user_id": user_id if user_id is not None else "",
        "rp_id": rp_id or "",
        "action": action or "",
        "status": status or "",
        "reason": reason or "",
        "method": method or "",
        "latency_ms": latency_ms if latency_ms is not None else "",
        "created_at": int(created_at) if created_at else "",
        "expires_at": int(expires_at) if expires_at else "",
        "client_ts": client_ts if client_ts is not None else "",
        "scenario": scenario or "",
        "payload_json": json.dumps(payload, ensure_ascii=True) if payload else "",
    }
    with METRICS_CSV.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writerow(row)
