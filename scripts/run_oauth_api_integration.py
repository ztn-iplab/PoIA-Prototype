#!/usr/bin/env python3
"""Manifest-bound HTTP/SQLite OAuth plus PoIA integration experiment."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from itsdangerous import TimestampSigner  # noqa: E402

from app import db, poia_metrics  # noqa: E402
from app.core import poia_store  # noqa: E402
from app.main import app  # noqa: E402
from app.model import ProofRecord  # noqa: E402
from app.routes import poia as poia_routes  # noqa: E402
from app.settings import SESSION_SECRET  # noqa: E402

TRIALS = 200
SCENARIOS = (
    "exact_request",
    "cross_action_substitution",
    "target_object_substitution",
    "scope_parameter_substitution",
)


class RecorderConfiguration:
    """Expose the production route's configuration switch without recording secrets."""

    enabled = True

    def __init__(self, configuration: str) -> None:
        self.manifest = {"configuration": configuration}

    def capture_state(self, *_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {"digest": "captured-by-runner"}

    def expected_decision_for(self, *_args: Any, **_kwargs: Any) -> str:
        return "runner_reference"

    def record(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency_summary(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "median_ms": statistics.median(values),
        "iqr_ms": percentile(values, 0.75) - percentile(values, 0.25),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
    }


def operation_count() -> int:
    with db.db_connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM experiment_api_operations").fetchone()[0])


def requested_operation(approved_scope: dict[str, Any], scenario: str) -> tuple[str, dict[str, Any], str]:
    action = "deploy_config"
    scope = deepcopy(approved_scope)
    reason = "approved"
    if scenario == "cross_action_substitution":
        action = "api_key_rotate"
        reason = "action_mismatch"
    elif scenario == "target_object_substitution":
        scope["object_id"] += "-substituted"
        reason = "scope_mismatch"
    elif scenario == "scope_parameter_substitution":
        scope["version"] = "v2"
        reason = "scope_mismatch"
    return action, scope, reason


def run(trials: int) -> list[dict[str, Any]]:
    rows = []
    poia_routes.POIA_EXPERIMENT_MODE = True
    poia_store.intents.clear()
    poia_store.challenges.clear()
    poia_store.proofs.clear()
    with tempfile.TemporaryDirectory(prefix="poia-oauth-confirmatory-") as directory:
        root = Path(directory)
        db.DB_PATH = root / "oauth-api.db"
        poia_metrics.METRICS_CSV = root / "metrics.csv"
        db.init_db()
        with db.db_connect() as conn:
            user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                ("oauth-confirmatory@example.invalid", "unused", int(time.time())),
            ).lastrowid
        session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
        session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")

        with TestClient(app) as client:
            client.cookies.set("session", session_cookie)
            for mode in ("oauth_only", "oauth_plus_poia"):
                poia_routes.track_a_recorder = RecorderConfiguration(
                    "session_only" if mode == "oauth_only" else "poia_webauthn"
                )
                for scenario in SCENARIOS:
                    for trial in range(trials):
                        approved_scope = {
                            "object_id": f"config-{mode}-{scenario}-{trial}",
                            "environment": "production",
                            "version": "v1",
                        }
                        issued = client.post(
                            "/api/poia/experiment/token/issue",
                            json={"intended_action": "deploy_config"},
                        )
                        if issued.status_code != 201:
                            raise RuntimeError(f"token issuance failed: {issued.text}")
                        token = issued.json()["access_token"]
                        intent_id = ""
                        if mode == "oauth_plus_poia":
                            started = client.post(
                                "/api/poia/experiment/token/intent/start",
                                json={"action": "deploy_config", "scope": approved_scope},
                            )
                            if started.status_code != 201:
                                raise RuntimeError(f"intent start failed: {started.text}")
                            intent_id = started.json()["intent_id"]
                            poia_store.approve_proof(
                                ProofRecord(intent_id, "test-fixture-proof", "approved", "Approved", 1),
                                time.time(),
                            )
                        action, requested_scope, mismatch_reason = requested_operation(
                            approved_scope, scenario
                        )
                        before = operation_count()
                        started_ns = time.perf_counter_ns()
                        response = client.post(
                            "/api/poia/experiment/token/action",
                            json={"action": action, "scope": requested_scope, "intent_id": intent_id},
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        elapsed_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
                        after = operation_count()
                        state_changed = after == before + 1
                        expected_accept = mode == "oauth_only" or scenario == "exact_request"
                        observed_accept = response.status_code == 201 and state_changed
                        observed_reason = (
                            "session_token_accepted"
                            if observed_accept and mode == "oauth_only"
                            else "approved"
                            if observed_accept
                            else response.json().get("reason", "unknown")
                        )
                        expected_reason = (
                            "session_token_accepted"
                            if mode == "oauth_only"
                            else "approved"
                            if scenario == "exact_request"
                            else mismatch_reason
                        )
                        correct = observed_accept == expected_accept and observed_reason == expected_reason
                        rows.append(
                            {
                                "mode": mode,
                                "scenario": scenario,
                                "trial": trial,
                                "http_status": response.status_code,
                                "expected_accept": int(expected_accept),
                                "observed_accept": int(observed_accept),
                                "state_changed": int(state_changed),
                                "expected_reason": expected_reason,
                                "observed_reason": observed_reason,
                                "correct": int(correct),
                                "action_endpoint_ms": elapsed_ms,
                            }
                        )
                        token = ""
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cells = []
    for mode in ("oauth_only", "oauth_plus_poia"):
        for scenario in SCENARIOS:
            subset = [row for row in rows if row["mode"] == mode and row["scenario"] == scenario]
            false_accepts = sum(row["observed_accept"] and not row["expected_accept"] for row in subset)
            false_rejects = sum(not row["observed_accept"] and row["expected_accept"] for row in subset)
            cells.append(
                {
                    "mode": mode,
                    "scenario": scenario,
                    "attempts": len(subset),
                    "accepted": sum(row["observed_accept"] for row in subset),
                    "protected_state_transitions": sum(row["state_changed"] for row in subset),
                    "false_acceptances": false_accepts,
                    "false_rejections": false_rejects,
                    "correct_decisions": sum(row["correct"] for row in subset),
                    "action_endpoint_latency": latency_summary([row["action_endpoint_ms"] for row in subset]),
                }
            )
    oauth_exact = next(cell for cell in cells if cell["mode"] == "oauth_only" and cell["scenario"] == "exact_request")
    poia_exact = next(cell for cell in cells if cell["mode"] == "oauth_plus_poia" and cell["scenario"] == "exact_request")
    return {
        "requests": len(rows),
        "cells": cells,
        "median_exact_request_overhead_ms": poia_exact["action_endpoint_latency"]["median_ms"] - oauth_exact["action_endpoint_latency"]["median_ms"],
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(materialized[0]))
        writer.writeheader()
        writer.writerows(materialized)


def write_table(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"# OAuth/API Integration: `{summary['run_id']}`",
        "",
        "| Mode | Scenario | Accepted | State transitions | Correct | False accept | False reject | Median ms | P95 ms |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cell in summary["cells"]:
        latency = cell["action_endpoint_latency"]
        lines.append(
            f"| {cell['mode']} | {cell['scenario']} | {cell['accepted']}/{cell['attempts']} | "
            f"{cell['protected_state_transitions']} | {cell['correct_decisions']}/{cell['attempts']} | "
            f"{cell['false_acceptances']} | {cell['false_rejections']} | {latency['median_ms']:.4f} | {latency['p95_ms']:.4f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--trials", type=int, default=TRIALS)
    parser.add_argument("--out-dir", default="experiments/oauth_api_integration")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    if args.trials != TRIALS:
        raise SystemExit(f"confirmatory sample size is fixed at {TRIALS}")
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        raise SystemExit("OAuth/API confirmatory runs require a clean working tree")
    out = ROOT / args.out_dir
    paths = {name: out / f"{args.run_id}-{suffix}" for name, suffix in {
        "manifest": "manifest.json", "trials": "trials.csv", "summary": "summary.json",
        "table": "table.md", "checksums": "checksums.sha256",
    }.items()}
    if any(path.exists() for path in paths.values()):
        raise SystemExit(f"run ID already exists: {args.run_id}")

    rows = run(args.trials)
    result = summarize(rows)
    summary = {"run_id": args.run_id, **result}
    if len(rows) != 1600 or not all(row["correct"] for row in rows):
        raise RuntimeError("OAuth/API confirmatory validity check failed")
    write_csv(paths["trials"], rows)
    write_json(paths["summary"], summary)
    write_table(paths["table"], summary)
    manifest = {
        "run_id": args.run_id,
        "repository_commit": git("rev-parse", "HEAD"),
        "tree_clean": not dirty,
        "repository_dirty": dirty,
        "trials_per_cell": args.trials,
        "requests": len(rows),
        "integration": "FastAPI TestClient plus SQLite protected state",
        "proof_source": "in-process approved-proof test fixture",
        "oauth_protocol_conformance_test": False,
        "contains_bearer_tokens_or_reusable_proofs": False,
        "python_version": platform.python_version(),
        "runner_sha256": sha256_file(Path(__file__)),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "oauth_api_preregistration.md"),
    }
    write_json(paths["manifest"], manifest)
    artifacts = (Path(__file__), paths["manifest"], paths["trials"], paths["summary"], paths["table"])
    paths["checksums"].write_text("\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in artifacts) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
