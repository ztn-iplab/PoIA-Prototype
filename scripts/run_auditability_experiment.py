#!/usr/bin/env python3
"""Manifest-bound paired auditability reconstruction experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.intent_codec import canonical_json  # noqa: E402

EVENTS = 200
FIELDS = ("principal", "action", "scope", "time", "context", "proof", "rationale")
REASONS = (
    "verified_intent_executed",
    "action_mismatch",
    "scope_mismatch",
    "principal_mismatch",
    "rp_mismatch",
    "constraints_mismatch",
    "expired",
)


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


def ground_truth(index: int) -> dict[str, Any]:
    domain = ("banking", "enterprise", "healthcare", "cloud_api")[index % 4]
    definitions = {
        "banking": ("transfer", {"account": f"account-{index % 17}", "beneficiary": f"beneficiary-{index % 23}", "amount": 100 + index % 19}),
        "enterprise": ("grant_role", {"target_user": f"employee-{index % 29}", "role": "reader", "tenant": f"tenant-{index % 7}"}),
        "healthcare": ("export_record", {"patient": f"patient-{index % 37}", "record_type": "lab_results", "purpose": "referral"}),
        "cloud_api": ("rotate_key", {"key": f"kms-key-{index % 41}", "project": f"project-{index % 13}", "region": "ap-northeast-1"}),
    }
    action, scope = definitions[domain]
    principal = f"principal-{index % 31}"
    context = {
        "rp_id": f"poia-{domain}",
        "user_id": principal,
        "workflow_id": f"workflow-{index}",
    }
    nonce = f"nonce-{index}"
    intent = {
        "action": action,
        "scope": scope,
        "context": context,
        "constraints": {"nonce": nonce, "expires_in_seconds": 60},
    }
    reason = REASONS[index % len(REASONS)]
    return {
        "incident_id": f"incident-{index:04d}",
        "domain": domain,
        "principal": principal,
        "action": action,
        "scope": scope,
        "time": 1_800_000_000 + index,
        "context": context,
        "proof": {
            "proof_id": f"proof-{index:04d}",
            "intent_hash": hashlib.sha256(canonical_json(intent)).hexdigest(),
            "nonce": nonce,
            "key_ref": f"device-key-{index % 11}",
        },
        "rationale": reason,
        "status": "executed" if reason == "verified_intent_executed" else "rejected",
    }


def baseline_log(truth: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "baseline-session-v1",
        "incident_id": truth["incident_id"],
        "timestamp": truth["time"],
        "user_id": truth["principal"],
        "session_id": f"session-{int(truth['incident_id'][-4:]) % 9}",
        "route": f"/{truth['action']}",
        "status": truth["status"],
        "message": "session-authorized request " + truth["status"],
    }


def poia_log(truth: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "poia-authorization-v1",
        "incident_id": truth["incident_id"],
        "timestamp": truth["time"],
        "principal": truth["principal"],
        "action": truth["action"],
        "scope": truth["scope"],
        "context": truth["context"],
        "proof": truth["proof"],
        "status": truth["status"],
        "decision_reason": truth["rationale"],
    }


def evidence(value: Any, quality: str = "exact") -> dict[str, Any]:
    return {"value": value, "quality": quality}


def reconstruct(log: dict[str, Any]) -> dict[str, dict[str, Any] | None]:
    if log["schema"] == "poia-authorization-v1":
        return {
            "principal": evidence(log.get("principal")),
            "action": evidence(log.get("action")),
            "scope": evidence(log.get("scope")),
            "time": evidence(log.get("timestamp")),
            "context": evidence(log.get("context")),
            "proof": evidence(log.get("proof")),
            "rationale": evidence(log.get("decision_reason")),
        }
    return {
        "principal": evidence(log.get("user_id")),
        "action": evidence(log.get("route", "").lstrip("/") or None),
        "scope": None,
        "time": evidence(log.get("timestamp")),
        "context": evidence({"session_id": log.get("session_id")}, "ambiguous"),
        "proof": None,
        "rationale": evidence(log.get("message"), "ambiguous"),
    }


def score_field(candidate: dict[str, Any] | None, expected: Any) -> str:
    if candidate is None or candidate.get("value") is None:
        return "missing"
    if candidate.get("quality") == "ambiguous":
        return "ambiguous"
    return "exact" if canonical_json({"value": candidate["value"]}) == canonical_json({"value": expected}) else "incorrect"


def reconstruct_and_score(log: dict[str, Any], truth: dict[str, Any]) -> tuple[list[dict[str, Any]], float]:
    started = time.perf_counter_ns()
    reconstructed = reconstruct(log)
    rows = []
    for field in FIELDS:
        candidate = reconstructed[field]
        rows.append(
            {
                "incident_id": truth["incident_id"],
                "log_type": "poia" if log["schema"].startswith("poia") else "baseline",
                "field": field,
                "score": score_field(candidate, truth[field]),
            }
        )
    return rows, (time.perf_counter_ns() - started) / 1_000_000


def run(events: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    truths = [ground_truth(index) for index in range(events)]
    logs = []
    field_rows = []
    incident_rows = []
    for truth in truths:
        for log_type, log in (("baseline", baseline_log(truth)), ("poia", poia_log(truth))):
            logs.append(log)
            scored, elapsed_ms = reconstruct_and_score(log, truth)
            field_rows.extend(scored)
            counts = {label: sum(row["score"] == label for row in scored) for label in ("exact", "ambiguous", "missing", "incorrect")}
            incident_rows.append(
                {
                    "incident_id": truth["incident_id"],
                    "domain": truth["domain"],
                    "outcome": truth["status"],
                    "ground_truth_reason": truth["rationale"],
                    "log_type": log_type,
                    **counts,
                    "completeness_percent": counts["exact"] / len(FIELDS) * 100,
                    "ambiguity_percent": counts["ambiguous"] / len(FIELDS) * 100,
                    "missing_percent": counts["missing"] / len(FIELDS) * 100,
                    "reconstruction_ms": elapsed_ms,
                }
            )
    modes = []
    for log_type in ("baseline", "poia"):
        subset = [row for row in incident_rows if row["log_type"] == log_type]
        modes.append(
            {
                "log_type": log_type,
                "incidents": len(subset),
                "reconstruction_completeness_mean_percent": statistics.mean(row["completeness_percent"] for row in subset),
                "ambiguity_rate_mean_percent": statistics.mean(row["ambiguity_percent"] for row in subset),
                "missing_evidence_rate_mean_percent": statistics.mean(row["missing_percent"] for row in subset),
                "incorrect_fields": sum(row["incorrect"] for row in subset),
                "automated_reconstruction_latency": latency_summary([row["reconstruction_ms"] for row in subset]),
            }
        )
    return truths, logs, field_rows, {"events_per_mode": events, "reconstruction_records": events * 2, "modes": modes, "incident_rows": incident_rows}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(materialized[0]))
        writer.writeheader()
        writer.writerows(materialized)


def write_table(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"# Auditability: `{summary['run_id']}`",
        "",
        "| Log type | Incidents | Completeness | Ambiguity | Missing | Incorrect fields | Median parser ms | P95 parser ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in summary["modes"]:
        latency = mode["automated_reconstruction_latency"]
        lines.append(
            f"| {mode['log_type']} | {mode['incidents']} | {mode['reconstruction_completeness_mean_percent']:.1f}% | "
            f"{mode['ambiguity_rate_mean_percent']:.1f}% | {mode['missing_evidence_rate_mean_percent']:.1f}% | "
            f"{mode['incorrect_fields']} | {latency['median_ms']:.6f} | {latency['p95_ms']:.6f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--events", type=int, default=EVENTS)
    parser.add_argument("--out-dir", default="experiments/auditability")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    if args.events != EVENTS:
        raise SystemExit(f"confirmatory sample size is fixed at {EVENTS}")
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        raise SystemExit("auditability confirmatory runs require a clean working tree")

    out = ROOT / args.out_dir
    paths = {name: out / f"{args.run_id}-{suffix}" for name, suffix in {
        "manifest": "manifest.json",
        "truth": "ground-truth.jsonl",
        "logs": "logs.jsonl",
        "fields": "field-scores.csv",
        "incidents": "incident-scores.csv",
        "summary": "summary.json",
        "table": "table.md",
        "checksums": "checksums.sha256",
    }.items()}
    if any(path.exists() for path in paths.values()):
        raise SystemExit(f"run ID already exists: {args.run_id}")

    truths, logs, field_rows, result = run(args.events)
    incident_rows = result.pop("incident_rows")
    summary = {"run_id": args.run_id, **result}
    if len(field_rows) != 2800 or any(row["score"] == "incorrect" for row in field_rows):
        raise RuntimeError("auditability validity check failed")
    write_jsonl(paths["truth"], truths)
    write_jsonl(paths["logs"], logs)
    write_csv(paths["fields"], field_rows)
    write_csv(paths["incidents"], incident_rows)
    write_json(paths["summary"], summary)
    write_table(paths["table"], summary)
    manifest = {
        "run_id": args.run_id,
        "repository_commit": git("rev-parse", "HEAD"),
        "tree_clean": not dirty,
        "repository_dirty": dirty,
        "events_per_mode": args.events,
        "reconstruction_records": args.events * 2,
        "field_scores": len(field_rows),
        "fields": list(FIELDS),
        "python_version": platform.python_version(),
        "runner_sha256": sha256_file(Path(__file__)),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "auditability_preregistration.md"),
        "contains_reusable_proofs": False,
    }
    write_json(paths["manifest"], manifest)
    artifacts = (Path(__file__), paths["manifest"], paths["truth"], paths["logs"], paths["fields"], paths["incidents"], paths["summary"], paths["table"])
    paths["checksums"].write_text("\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in artifacts) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
