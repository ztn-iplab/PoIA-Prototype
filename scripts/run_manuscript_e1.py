#!/usr/bin/env python3
"""Run manuscript E1 exact-intent matching experiments."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import platform
import random
import statistics
import subprocess
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "experiments" / "manuscript_20260824" / "scenarios" / "e1_exact_intent_matching.json"
OUTPUT_ROOT = ROOT / "experiments" / "manuscript_20260824" / "runs"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.intent_codec import build_intent, canonical_json
from app.model import ChallengeRecord, InMemoryPoIA, IntentRecord, ProofRecord, nonce_mismatch_reason


def git(args: List[str]) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: List[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    pos = (len(ordered) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def load_scenarios() -> List[Dict[str, str]]:
    document = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    scenarios = document["scenarios"]
    ids = [scenario["id"] for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate E1 scenario id")
    return scenarios


def reverse_objects(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: reverse_objects(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reverse_objects(item) for item in value]
    return value


def base_intent(trial: int, rng: random.Random) -> Dict[str, Any]:
    return build_intent(
        action="grant-role",
        scope={
            "target_resource": f"tenant-resource-{trial}",
            "principal": f"user-{trial % 23}",
            "role": "user",
            "permissions": ["read"],
            "quantity": rng.randint(10, 10_000),
            "label": "caf\u00e9",
        },
        context={
            "user_id": 7,
            "rp_id": "poia.local",
            "endpoint": "/authorize-action",
            "session_id": f"session-{trial}",
            "device_id": "device-primary",
            "workflow_id": f"workflow-{trial}",
        },
    )


def fresh_store(intent: Dict[str, Any], trial: int) -> Tuple[InMemoryPoIA, float]:
    created_at = 1_900_000_000.0 + trial * 100.0
    store = InMemoryPoIA()
    store.intents["intent-1"] = IntentRecord("intent-1", intent, created_at)
    store.challenges["intent-1"] = ChallengeRecord("intent-1", f"nonce-{trial}", created_at + 60.0)
    store.proofs["intent-1"] = ProofRecord("intent-1", "opaque-e1-proof", "pending", "Pending", 0)
    ok, reason = store.approve_proof(
        ProofRecord("intent-1", "opaque-e1-proof", "approved", "Approved", 0),
        created_at + 0.01,
    )
    if not ok:
        raise RuntimeError(f"fixture approval failed: {reason}")
    return store, created_at


def mutate(intent: Dict[str, Any], mutation: str, trial: int) -> Dict[str, Any]:
    requested = copy.deepcopy(intent)
    if mutation == "none":
        return requested
    if mutation == "reverse_object_order":
        return reverse_objects(requested)
    if mutation == "unicode_and_integer_float_equivalence":
        requested["scope"]["label"] = unicodedata.normalize("NFD", requested["scope"]["label"])
        requested["scope"]["quantity"] = float(requested["scope"]["quantity"])
        requested["constraints"]["expires_in_seconds"] = 60.0
        return requested
    if mutation == "replace_action":
        requested["action"] = "revoke-role"
    elif mutation == "replace_target_resource":
        requested["scope"]["target_resource"] = f"other-resource-{trial}"
    elif mutation == "replace_role":
        requested["scope"]["role"] = "administrator"
    elif mutation == "expand_permissions":
        requested["scope"]["permissions"] = ["read", "export"]
    elif mutation == "replace_quantity":
        requested["scope"]["quantity"] += 1000
    elif mutation == "replace_rp":
        requested["context"]["rp_id"] = "attacker.local"
    elif mutation == "replace_endpoint":
        requested["context"]["endpoint"] = "/execute-action"
    elif mutation == "replace_session":
        requested["context"]["session_id"] = f"attacker-session-{trial}"
    elif mutation == "replace_device":
        requested["context"]["device_id"] = "device-secondary"
    elif mutation == "omit_scope":
        requested.pop("scope", None)
    elif mutation == "case_change_action":
        requested["action"] = requested["action"].upper()
    elif mutation == "quantity_as_string":
        requested["scope"]["quantity"] = str(requested["scope"]["quantity"])
    elif mutation == "unicode_key_collision":
        requested["scope"] = {"caf\u00e9": 1, "cafe\u0301": 2}
    elif mutation == "nonfinite_number":
        requested["scope"]["quantity"] = math.nan
    elif mutation in {"replace_nonce", "submit_after_expiry"}:
        pass
    else:
        raise ValueError(f"unsupported mutation {mutation}")
    return requested


def intent_hash(intent: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(intent)).hexdigest()


def execute(scenario: Mapping[str, str], trial: int, rng: random.Random) -> Dict[str, Any]:
    approved = base_intent(trial, rng)
    store, created_at = fresh_store(approved, trial)
    requested = mutate(approved, scenario["mutation"], trial)
    now = created_at + 10.0
    start = time.perf_counter_ns()
    canonicalization_error = ""
    try:
        approved_hash = intent_hash(approved)
        requested_hash = intent_hash(requested)
        if scenario["mutation"] == "replace_nonce":
            reason = nonce_mismatch_reason(store.challenges["intent-1"], f"other-nonce-{trial}")
            accepted = reason is None
        else:
            if scenario["mutation"] == "submit_after_expiry":
                now = created_at + 61.0
            accepted, reason, _, _ = store.reserve_execution("intent-1", 7, now, requested)
    except (TypeError, ValueError) as exc:
        accepted = False
        reason = "canonicalization_error"
        canonicalization_error = f"{type(exc).__name__}: {exc}"
        approved_hash = intent_hash(approved)
        requested_hash = "unrepresentable"
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    decision = "accept" if accepted else "reject"
    return {
        "experiment": "E1_exact_intent_matching",
        "scenario_id": scenario["id"],
        "category": scenario["category"],
        "class": scenario["class"],
        "mutation_class": scenario["mutation_class"],
        "mutation": scenario["mutation"],
        "trial": trial,
        "expected_decision": scenario["expected_decision"],
        "decision": decision,
        "correct": decision == scenario["expected_decision"],
        "false_acceptance": scenario["class"] == "invalid" and decision == "accept",
        "false_rejection": scenario["class"] == "valid" and decision == "reject",
        "rejection_reason": "" if accepted else reason,
        "latency_ms": latency_ms,
        "approved_intent_sha256": approved_hash,
        "requested_intent_sha256": requested_hash,
        "canonicalization_error": canonicalization_error,
    }


def grouped(rows: Iterable[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row[key]), []).append(row)
    out = []
    for name in sorted(groups):
        selected = groups[name]
        latencies = [float(row["latency_ms"]) for row in selected]
        out.append({
            key: name,
            "cases": len(selected),
            "correct": sum(row["correct"] for row in selected),
            "errors": sum(not row["correct"] for row in selected),
            "false_acceptances": sum(row["false_acceptance"] for row in selected),
            "false_rejections": sum(row["false_rejection"] for row in selected),
            "median_latency_ms": statistics.median(latencies),
            "p95_latency_ms": percentile(latencies, 0.95),
        })
    return out


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [row for row in rows if row["class"] == "valid"]
    invalid = [row for row in rows if row["class"] == "invalid"]
    latencies = [float(row["latency_ms"]) for row in rows]
    reasons: Dict[str, int] = {}
    for row in invalid:
        reasons[row["rejection_reason"] or "accepted"] = reasons.get(row["rejection_reason"] or "accepted", 0) + 1
    return {
        "total_cases": len(rows),
        "valid_cases": len(valid),
        "invalid_cases": len(invalid),
        "invalid_acceptances": sum(row["false_acceptance"] for row in invalid),
        "valid_rejections": sum(row["false_rejection"] for row in valid),
        "far": sum(row["false_acceptance"] for row in invalid) / len(invalid),
        "frr": sum(row["false_rejection"] for row in valid) / len(valid),
        "error_categories": "none" if all(row["correct"] for row in rows) else "see raw trial records",
        "rejection_reasons": dict(sorted(reasons.items())),
        "latency_ms": {
            "median": statistics.median(latencies),
            "mean": statistics.fmean(latencies),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
        "by_category": grouped(rows, "category"),
        "by_mutation_class": grouped(rows, "mutation_class"),
    }


def write_run(run_dir: Path, manifest: Dict[str, Any], rows: List[Dict[str, Any]]) -> None:
    raw = run_dir / "raw"
    analysis = run_dir / "analysis"
    tables = run_dir / "tables"
    raw.mkdir(parents=True, exist_ok=False)
    analysis.mkdir()
    tables.mkdir()
    with (raw / "trials.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    with (raw / "trials.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {**manifest, "summary": summarize(rows)}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (analysis / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"# E1 Exact Intent Matching: {manifest['run_id']}",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total cases | {summary['summary']['total_cases']} |",
        f"| Invalid cases | {summary['summary']['invalid_cases']} |",
        f"| Invalid acceptances | {summary['summary']['invalid_acceptances']} |",
        f"| FAR | {summary['summary']['far']:.6f} |",
        f"| Valid cases | {summary['summary']['valid_cases']} |",
        f"| Valid rejections | {summary['summary']['valid_rejections']} |",
        f"| FRR | {summary['summary']['frr']:.6f} |",
        f"| Median verifier latency | {summary['summary']['latency_ms']['median']:.6f} ms |",
        "",
        "| Category | Cases | Correct | Errors |",
        "|---|---:|---:|---:|",
    ]
    for item in summary["summary"]["by_category"]:
        lines.append(f"| {item['category']} | {item['cases']} | {item['correct']} | {item['errors']} |")
    (tables / "e1_exact_intent_matching.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    paths = [run_dir / "manifest.json", raw / "trials.csv", raw / "trials.jsonl", analysis / "summary.json", tables / "e1_exact_intent_matching.md"]
    (analysis / "checksums.sha256").write_text(
        "\n".join(f"{sha256(path)}  {path.relative_to(run_dir)}" for path in sorted(paths)) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260824)
    parser.add_argument("--run-id", default="e1-exact-intent-20260824")
    args = parser.parse_args()
    scenarios = load_scenarios()
    rng = random.Random(args.seed)
    for scenario in scenarios:
        for trial in range(1, args.warmup + 1):
            execute(scenario, -trial, rng)
    rows = [
        execute(scenario, trial, rng)
        for scenario in scenarios
        for trial in range(1, args.trials + 1)
    ]
    run_dir = OUTPUT_ROOT / args.run_id
    manifest = {
        "schema_version": "1.0.0",
        "experiment": "E1_exact_intent_matching",
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials_per_scenario": args.trials,
        "warmup_trials_per_scenario": args.warmup,
        "random_seed": args.seed,
        "scenario_file": str(SCENARIOS.relative_to(ROOT)),
        "scenario_file_sha256": sha256(SCENARIOS),
        "rp_commit": git(["rev-parse", "HEAD"]),
        "rp_tree": git(["rev-parse", "HEAD^{tree}"]),
        "rp_dirty": bool(git(["status", "--porcelain"])),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "evidence_class": "verifier_state_machine_and_canonicalization",
    }
    write_run(run_dir, manifest, rows)
    print(json.dumps({"run_id": args.run_id, "run_dir": str(run_dir), "trials": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
