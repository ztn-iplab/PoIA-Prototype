#!/usr/bin/env python3
"""Track A scenario validation, manifest creation, and safe evidence writing."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

ROOT = Path(__file__).resolve().parents[1]
TRACK_A = ROOT / "experiments" / "track_a"
SCENARIO_FILE = TRACK_A / "scenarios" / "security_effectiveness.json"

CONFIGURATIONS = {"session_only", "poia_webauthn", "poia_zt_authenticator"}
REQUIRED_SCENARIOS = {
    "replay",
    "relay_phishing",
    "session_hijacking_or_misuse",
    "request_tampering",
    "token_reuse",
    "confused_deputy",
    "multi_step_abuse",
}
DECISION_FIELDS = (
    "timestamp_utc", "run_id", "batch_id", "attempt_n", "request_id",
    "scenario_id", "scenario_category", "configuration", "signing_backend",
    "principal", "action", "scope", "context", "workflow_id", "nonce",
    "proof_id", "canonical_intent_hash", "expected_decision", "decision",
    "rejection_reason", "http_status", "state_changed", "latency_ms",
    "rp_commit", "authenticator_commit", "scenario_commit", "random_seed",
)
FORBIDDEN_EVIDENCE_KEYS = {
    "authorization", "bearer", "cookie", "password", "private_key",
    "secret", "session", "signature", "token",
}
SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$")


def _run_git(args: List[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_safe_id(label: str, value: str) -> None:
    if not SAFE_ID.fullmatch(value):
        raise ValueError(f"{label} must match {SAFE_ID.pattern!r}")


def load_scenarios(path: Path = SCENARIO_FILE) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if set(document) != {"schema_version", "scenario_set", "scenarios"}:
        raise ValueError("scenario document has missing or unknown top-level fields")
    if document["scenario_set"] != "track_a_security_effectiveness":
        raise ValueError("unexpected scenario_set")
    if not re.fullmatch(r"\d+\.\d+\.\d+", document["schema_version"]):
        raise ValueError("schema_version must use semantic version syntax")
    scenarios = document["scenarios"]
    if not isinstance(scenarios, list):
        raise ValueError("scenarios must be a list")
    ids = set()
    required = {
        "id", "category", "description", "protected_action", "attack_mutation",
        "expected_decision", "expected_rejection_reasons", "prohibited_state_change",
    }
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != required:
            raise ValueError("each scenario must contain exactly the documented fields")
        scenario_id = scenario["id"]
        if scenario_id in ids:
            raise ValueError(f"duplicate scenario id: {scenario_id}")
        validate_safe_id("scenario id", scenario_id)
        ids.add(scenario_id)
        if scenario["expected_decision"] != "reject":
            raise ValueError(f"attack scenario {scenario_id} must expect rejection")
        if not scenario["expected_rejection_reasons"]:
            raise ValueError(f"scenario {scenario_id} has no rejection taxonomy")
    if ids != REQUIRED_SCENARIOS:
        raise ValueError(f"scenario ids differ from preregistration: {sorted(ids)}")
    return document


def git_state(repo: Path) -> Dict[str, Any]:
    return {
        "commit": _run_git(["rev-parse", "HEAD"], repo),
        "tree": _run_git(["rev-parse", "HEAD^{tree}"], repo),
        "dirty": bool(_run_git(["status", "--porcelain"], repo)),
    }


def create_manifest(
    *, run_id: str, batch_id: str, configuration: str, random_seed: int,
    authenticator_repo: Path | None = None,
    experimental_environment: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    validate_safe_id("run_id", run_id)
    validate_safe_id("batch_id", batch_id)
    if configuration not in CONFIGURATIONS:
        raise ValueError(f"unsupported configuration: {configuration}")
    scenarios = load_scenarios()
    rp = git_state(ROOT)
    authenticator = None
    if authenticator_repo is not None:
        authenticator = git_state(authenticator_repo.resolve())
    if configuration == "poia_zt_authenticator" and authenticator is None:
        raise ValueError("ZT-Authenticator runs require --authenticator-repo")
    return {
        "schema_version": "1.0.0",
        "experiment": "track_a",
        "run_id": run_id,
        "batch_id": batch_id,
        "configuration": configuration,
        "random_seed": random_seed,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_size_per_scenario": 200,
        "scenario_file": str(SCENARIO_FILE.relative_to(ROOT)),
        "scenario_schema_version": scenarios["schema_version"],
        "scenario_file_sha256": sha256_file(SCENARIO_FILE),
        "rp_repository": rp,
        "authenticator_repository": authenticator,
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor_count": os.cpu_count(),
        },
        "experimental_environment": dict(experimental_environment or {
            "browser_or_client_runtime": "not_recorded",
            "authenticator_platform": "not_recorded",
            "container_runtime": "not_recorded",
            "network_rtt_ms": None,
            "database_backend": "not_recorded",
            "clock_source": "time.time and time.perf_counter_ns",
        }),
        "sensitive_data_policy": "No credentials, tokens, raw signatures, secrets, or direct personal identifiers.",
    }


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")
    temporary.replace(path)


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key).lower()
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def append_decision(path: Path, record: Mapping[str, Any]) -> None:
    missing = [field for field in DECISION_FIELDS if field not in record]
    unknown = [field for field in record if field not in DECISION_FIELDS]
    if missing or unknown:
        raise ValueError(f"invalid decision fields; missing={missing}, unknown={unknown}")
    forbidden = sorted(set(_walk_keys(record)) & FORBIDDEN_EVIDENCE_KEYS)
    if forbidden:
        raise ValueError(f"decision contains forbidden evidence keys: {forbidden}")
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def state_digest(snapshot: Mapping[str, Any]) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
