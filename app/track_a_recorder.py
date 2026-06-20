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
    sensitive = {"account_number", "external_account", "name", "object_id", "reference"}
    for key, value in scope.items():
        if key in sensitive and value not in (None, ""):
            safe[key] = _opaque(key, value)
        else:
            safe[key] = value
    return safe


def _safe_intent(intent: Mapping[str, Any]) -> Dict[str, Any]:
    context = intent.get("context", {})
    return {
        "action": intent.get("action"),
        "scope": _safe_scope(intent.get("scope", {})),
        "context": {
            "user_id": _opaque("principal", context.get("user_id", "unknown")),
            "rp_id": context.get("rp_id"),
            "workflow_id": context.get("workflow_id"),
            "on_behalf_of": (
                _opaque("delegated_principal", context.get("on_behalf_of"))
                if context.get("on_behalf_of")
                else None
            ),
        },
        "constraints": intent.get("constraints", {}),
    }


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
                "workflows_consumed": conn.execute(
                    "SELECT COUNT(*) FROM poia_workflows WHERE user_id = ? AND status = 'consumed'",
                    (principal_id,),
                ).fetchone()[0],
                "api_operations": conn.execute(
                    "SELECT COUNT(*) FROM experiment_api_operations WHERE user_id = ?",
                    (principal_id,),
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

    def attach_external_state(
        self, snapshot: Mapping[str, Any], label: str, state: Mapping[str, Any]
    ) -> Dict[str, Any]:
        combined = {key: value for key, value in snapshot.items() if key != "digest"}
        combined[label] = dict(state)
        combined["digest"] = _digest(combined)
        return combined

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
        approved_intent_body: Optional[Mapping[str, Any]] = None,
        requested_intent_body: Optional[Mapping[str, Any]] = None,
        latency_ms: Optional[float] = None,
        latency_started_at_utc: Optional[float] = None,
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
        finished_ns = time.perf_counter_ns()
        finished_at_utc = time.time()
        measured_latency_ms = (
            latency_ms
            if latency_ms is not None
            else (finished_ns - started_ns) / 1_000_000
        )
        record = {
            "timestamp_utc": datetime.fromtimestamp(finished_at_utc, timezone.utc).isoformat(),
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
                "on_behalf_of": (
                    _opaque("delegated_principal", context.get("on_behalf_of"))
                    if context.get("on_behalf_of")
                    else None
                ),
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
            "latency_ms": measured_latency_ms,
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
        request_path = self.run_dir / "requests" / f"{attempt_n:04d}-{request_id}.json"
        timing_path = self.run_dir / "timings" / f"{attempt_n:04d}-{request_id}.json"
        request_evidence = {
            "schema_version": "1.0.0",
            "run_id": self.manifest["run_id"],
            "request_id": request_id,
            "attempt_n": attempt_n,
            "approved_intent": _safe_intent(approved_intent_body or intent_body),
            "requested_intent": _safe_intent(requested_intent_body or intent_body),
        }
        timing_evidence = {
            "schema_version": "1.0.0",
            "run_id": self.manifest["run_id"],
            "request_id": request_id,
            "attempt_n": attempt_n,
            "clock_source": (
                "time.time"
                if latency_started_at_utc is not None
                else "time.perf_counter_ns"
            ),
            "latency_started_at_utc": (
                datetime.fromtimestamp(latency_started_at_utc, timezone.utc).isoformat()
                if latency_started_at_utc is not None
                else None
            ),
            "finished_at_utc": datetime.fromtimestamp(finished_at_utc, timezone.utc).isoformat(),
            "endpoint_started_perf_counter_ns": started_ns,
            "endpoint_finished_perf_counter_ns": finished_ns,
            "latency_ms": measured_latency_ms,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._lock:
            with decision_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            temporary = snapshot_path.with_suffix(".json.tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(evidence, handle, indent=2, sort_keys=True, ensure_ascii=True)
                handle.write("\n")
            temporary.replace(snapshot_path)
            request_temporary = request_path.with_suffix(".json.tmp")
            with request_temporary.open("w", encoding="utf-8") as handle:
                json.dump(request_evidence, handle, indent=2, sort_keys=True, ensure_ascii=True)
                handle.write("\n")
            request_temporary.replace(request_path)
            timing_temporary = timing_path.with_suffix(".json.tmp")
            with timing_temporary.open("w", encoding="utf-8") as handle:
                json.dump(timing_evidence, handle, indent=2, sort_keys=True, ensure_ascii=True)
                handle.write("\n")
            timing_temporary.replace(timing_path)

    def record_rejection(
        self,
        *,
        request: Any,
        intent_id: str,
        intent_body: Mapping[str, Any],
        nonce: Optional[str],
        rejection_reason: str,
        http_status: int,
        started_ns: int,
        created_at: Optional[float] = None,
    ) -> None:
        if not self.enabled:
            return
        context = intent_body.get("context", {})
        principal_id = context.get("user_id")
        if not isinstance(principal_id, int):
            raise RuntimeError("Track A rejection recording requires an integer experiment principal")
        before = self.capture_state(
            principal_id,
            str(intent_body.get("action") or "unknown"),
            intent_body.get("scope", {}),
        )
        self.record(
            request=request,
            intent_id=intent_id,
            intent_body=intent_body,
            nonce=nonce,
            expected_decision=self.expected_decision_for(request),
            decision="reject",
            rejection_reason=rejection_reason,
            http_status=http_status,
            started_ns=started_ns,
            before=before,
            after=before,
            latency_ms=(
                max(0.0, (time.time() - created_at) * 1000.0)
                if created_at is not None
                else None
            ),
            latency_started_at_utc=created_at,
        )


track_a_recorder = TrackARecorder.from_environment()
