"""Manifest-bound Track A decision and protected-state evidence recorder."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

CONFIGURATION_BACKENDS = {
    "session_only": None,
    "poia_webauthn": "webauthn",
    "poia_zt_authenticator": "zt_authenticator",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _opaque(label: str, value: Any) -> str:
    return f"{label}_{hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:16]}"


def _safe_scope(scope: Mapping[str, Any]) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    sensitive = {"account_number", "external_account", "name", "reference"}
    for key, value in scope.items():
        if key in sensitive and value not in (None, ""):
            safe[key] = _opaque(key, value)
        else:
            safe[key] = value
    return safe


class TrackARecorder:
    def __init__(
        self,
        manifest_path: Optional[Path],
        scenario_id: str = "",
        expected_decision: str = "",
    ) -> None:
        self.enabled = manifest_path is not None
        self._lock = threading.RLock()
        self._attempt = 0
        self.manifest: Dict[str, Any] = {}
        self.run_dir: Optional[Path] = None
        self.scenario_id = scenario_id
        self.expected_decision = expected_decision
        if not self.enabled:
            return

        assert manifest_path is not None
        resolved = manifest_path.expanduser().resolve()
        with resolved.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
        required = {
            "run_id", "batch_id", "configuration", "random_seed",
            "rp_repository", "authenticator_repository",
        }
        missing = sorted(required - set(manifest))
        if missing:
            raise RuntimeError(f"Track A manifest is missing fields: {missing}")
        if manifest["configuration"] not in CONFIGURATION_BACKENDS:
            raise RuntimeError("Track A manifest has an unsupported configuration")
        if resolved.name != "manifest.json":
            raise RuntimeError("Track A manifest filename must be manifest.json")
        if resolved.parent.name != manifest["run_id"]:
            raise RuntimeError("Track A manifest run_id does not match its directory")
        self.manifest = manifest
        self.run_dir = resolved.parent
        for child in ("decisions", "state_snapshots", "timings", "requests"):
            (self.run_dir / child).mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_environment(cls) -> "TrackARecorder":
        raw_path = os.getenv("POIA_TRACK_A_MANIFEST", "").strip()
        scenario_id = os.getenv("POIA_TRACK_A_SCENARIO_ID", "").strip()
        expected = os.getenv("POIA_TRACK_A_EXPECTED_DECISION", "").strip()
        return cls(
            Path(raw_path) if raw_path else None,
            scenario_id=scenario_id,
            expected_decision=expected,
        )

    def expected_decision_for(self, request: Any) -> str:
        decision = request.headers.get("x-poia-expected-decision") or self.expected_decision
        if decision not in {"accept", "reject"}:
            raise RuntimeError(
                "Track A recording requires POIA_TRACK_A_EXPECTED_DECISION or "
                "X-PoIA-Expected-Decision set to accept or reject"
            )
        return decision

    def next_attempt(self, explicit: Optional[str]) -> int:
        if explicit:
            attempt = int(explicit)
            if attempt < 1:
                raise ValueError("Track A attempt number must be positive")
            return attempt
        with self._lock:
            self._attempt += 1
            return self._attempt

    def capture_state(self, principal_id: int, action: str, scope: Mapping[str, Any]) -> Dict[str, Any]:
        """Capture only synthetic protected-state facts needed to detect effects."""
        from .db import db_connect

        account_id = scope.get("from_account", scope.get("account_id"))
        with db_connect() as conn:
            account = None
            if account_id not in (None, ""):
                account = conn.execute(
                    "SELECT id, balance FROM accounts WHERE id = ? AND user_id = ?",
                    (account_id, principal_id),
                ).fetchone()
            counts = {
                "transactions": conn.execute(
                    "SELECT COUNT(*) FROM transactions JOIN accounts ON transactions.account_id = accounts.id WHERE accounts.user_id = ?",
                    (principal_id,),
                ).fetchone()[0],
                "beneficiaries": conn.execute(
                    "SELECT COUNT(*) FROM beneficiaries WHERE user_id = ?", (principal_id,)
                ).fetchone()[0],
                "audit_entries": conn.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", (principal_id,)
                ).fetchone()[0],
            }
        snapshot: Dict[str, Any] = {
            "principal": _opaque("principal", principal_id),
            "action": action,
            "counts": counts,
        }
        if account is not None:
            snapshot["account"] = {
                "id": _opaque("account", account["id"]),
                "balance": account["balance"],
            }
        snapshot["digest"] = _digest(snapshot)
        return snapshot

    def record(
        self,
        *,
        request: Any,
        intent_id: str,
        intent_body: Mapping[str, Any],
        nonce: Optional[str],
        expected_decision: str,
        decision: str,
        rejection_reason: Optional[str],
        http_status: int,
        started_ns: int,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
    ) -> None:
        if not self.enabled or self.run_dir is None:
            return
        request_id = request.headers.get("x-poia-request-id") or str(uuid.uuid4())
        attempt_n = self.next_attempt(request.headers.get("x-poia-attempt"))
        scenario_id = request.headers.get("x-poia-scenario-id") or self.scenario_id
        if not scenario_id:
            raise RuntimeError("Track A recording requires POIA_TRACK_A_SCENARIO_ID or X-PoIA-Scenario-Id")
        scenario_category = request.headers.get("x-poia-scenario-category") or scenario_id
        configuration = self.manifest["configuration"]
        context = intent_body.get("context", {})
        workflow_id = context.get("workflow_id") or intent_body.get("workflow_id")
        rp_commit = self.manifest["rp_repository"]["commit"]
        authenticator = self.manifest.get("authenticator_repository")
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": self.manifest["run_id"],
            "batch_id": self.manifest["batch_id"],
            "attempt_n": attempt_n,
            "request_id": request_id,
            "scenario_id": scenario_id,
            "scenario_category": scenario_category,
            "configuration": configuration,
            "signing_backend": CONFIGURATION_BACKENDS[configuration],
            "principal": _opaque("principal", context.get("user_id", "unknown")),
            "action": intent_body.get("action", "unknown"),
            "scope": _safe_scope(intent_body.get("scope", {})),
            "context": {
                "rp_id": context.get("rp_id"),
                "on_behalf_of": context.get("on_behalf_of"),
            },
            "workflow_id": workflow_id,
            "nonce": _opaque("nonce", nonce) if nonce else None,
            "proof_id": _opaque("proof", intent_id),
            "canonical_intent_hash": _digest(intent_body),
            "expected_decision": expected_decision,
            "decision": decision,
            "rejection_reason": rejection_reason,
            "http_status": http_status,
            "state_changed": before.get("digest") != after.get("digest"),
            "latency_ms": (time.perf_counter_ns() - started_ns) / 1_000_000,
            "rp_commit": rp_commit,
            "authenticator_commit": authenticator["commit"] if authenticator else None,
            "scenario_commit": rp_commit,
            "random_seed": self.manifest["random_seed"],
        }
        evidence = {
            "schema_version": "1.0.0",
            "run_id": self.manifest["run_id"],
            "request_id": request_id,
            "attempt_n": attempt_n,
            "before": before,
            "after": after,
            "state_changed": record["state_changed"],
        }
        decision_path = self.run_dir / "decisions" / "decisions.jsonl"
        snapshot_path = self.run_dir / "state_snapshots" / f"{attempt_n:04d}-{request_id}.json"
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._lock:
            with decision_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            temporary = snapshot_path.with_suffix(".json.tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(evidence, handle, indent=2, sort_keys=True, ensure_ascii=True)
                handle.write("\n")
            temporary.replace(snapshot_path)


track_a_recorder = TrackARecorder.from_environment()
