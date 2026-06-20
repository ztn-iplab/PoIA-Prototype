#!/usr/bin/env python3
"""Run the preregistered backend-independent Track A correctness matrix."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import platform
import random
import statistics
import subprocess
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from analyze_track_a import percentile, wilson_interval
except ModuleNotFoundError:
    from scripts.analyze_track_a import percentile, wilson_interval

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_PATH = ROOT / "experiments" / "track_a" / "scenarios" / "functional_correctness.json"

from app.intent_codec import build_intent, canonical_json
from app.model import (
    ChallengeRecord,
    InMemoryPoIA,
    IntentRecord,
    ProofRecord,
    nonce_mismatch_reason,
)


def git(args: List[str]) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_scenarios() -> List[Dict[str, str]]:
    document = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    if document.get("scenario_set") != "track_a_functional_correctness_verifier_only":
        raise ValueError("unexpected functional scenario set")
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 16:
        raise ValueError("functional scenario set must contain exactly 16 cases")
    ids = [scenario["id"] for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("functional scenario ids must be unique")
    return scenarios


def fresh_store(trial: int, amount: int) -> Tuple[InMemoryPoIA, Dict[str, Any], float]:
    created_at = 1_900_000_000.0 + trial * 100.0
    intent = build_intent(
        action="transfer",
        scope={
            "amount": amount,
            "currency": "USD",
            "target_object": f"synthetic-target-{trial}",
            "label": "caf\u00e9",
        },
        context={
            "user_id": 7,
            "rp_id": "poia.local",
            "workflow_id": f"workflow-{trial}",
        },
    )
    store = InMemoryPoIA()
    store.intents["intent-1"] = IntentRecord("intent-1", intent, created_at)
    store.challenges["intent-1"] = ChallengeRecord(
        "intent-1", f"nonce-{trial}", created_at + 60.0
    )
    store.proofs["intent-1"] = ProofRecord(
        "intent-1", "opaque-verifier-only", "pending", "Pending", 0
    )
    approved, reason = store.approve_proof(
        ProofRecord("intent-1", "opaque-verifier-only", "approved", "Approved", 0),
        created_at + 0.01,
    )
    if not approved:
        raise RuntimeError(f"fixture approval failed: {reason}")
    return store, intent, created_at


def reverse_objects(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: reverse_objects(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reverse_objects(item) for item in value]
    return value


def execute_case(
    scenario: Dict[str, str], trial: int, rng: random.Random
) -> Dict[str, Any]:
    amount = rng.randint(10, 10_000)
    store, approved_intent, created_at = fresh_store(trial, amount)
    requested = copy.deepcopy(approved_intent)
    principal = 7
    now = created_at + 10.0
    mutation = scenario["mutation"]
    start_ns = time.perf_counter_ns()

    if mutation == "replace_action":
        requested["action"] = "beneficiary_add"
    elif mutation == "replace_amount":
        requested["scope"]["amount"] = amount + 1
    elif mutation == "replace_currency_only":
        requested["scope"]["currency"] = "EUR"
    elif mutation == "replace_target":
        requested["scope"]["target_object"] = f"different-target-{trial}"
    elif mutation == "replace_session_principal":
        principal = 8
    elif mutation == "replace_rp":
        requested["context"]["rp_id"] = "attacker.local"
    elif mutation == "replace_nonce":
        reason = nonce_mismatch_reason(store.challenges["intent-1"], f"other-nonce-{trial}")
        accepted = reason is None
    elif mutation == "reuse_consumed_proof":
        first = store.reserve_execution("intent-1", principal, now, requested)
        if not first[0]:
            raise RuntimeError(f"nonce reuse fixture failed: {first[1]}")
        accepted, reason, _, _ = store.reserve_execution(
            "intent-1", principal, now + 0.01, requested
        )
    elif mutation == "submit_after_expiry":
        now = created_at + 61.0
    elif mutation == "submit_at_59_9_seconds":
        now = created_at + 59.9
    elif mutation == "submit_at_60_1_seconds":
        now = created_at + 60.1
    elif mutation == "replace_validity_constraint":
        requested["constraints"]["expires_in_seconds"] = 120
    elif mutation == "reverse_object_order":
        requested = reverse_objects(requested)
    elif mutation == "nfd_and_integer_float":
        requested["scope"]["label"] = unicodedata.normalize(
            "NFD", requested["scope"]["label"]
        )
        requested["scope"]["amount"] = float(amount)
        requested["constraints"]["expires_in_seconds"] = 60.0
    elif mutation == "replace_workflow_id":
        requested["context"]["workflow_id"] = f"other-workflow-{trial}"
    elif mutation != "none":
        raise ValueError(f"unsupported mutation: {mutation}")

    if mutation not in {"replace_nonce", "reuse_consumed_proof"}:
        accepted, reason, _, _ = store.reserve_execution(
            "intent-1", principal, now, requested
        )
    decision = "accept" if accepted else "reject"
    expected = scenario["expected_decision"]
    latency_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    return {
        "scenario_id": scenario["id"],
        "category": scenario["category"],
        "trial": trial,
        "expected_decision": expected,
        "decision": decision,
        "correct": decision == expected,
        "false_acceptance": expected == "reject" and decision == "accept",
        "false_rejection": expected == "accept" and decision == "reject",
        "reason": reason,
        "latency_ms": latency_ms,
        "approved_intent_sha256": hashlib.sha256(canonical_json(approved_intent)).hexdigest(),
        "requested_intent_sha256": hashlib.sha256(canonical_json(requested)).hexdigest(),
    }


def summarize(rows: List[Dict[str, Any]], scenarios: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    summaries = []
    for scenario in scenarios:
        selected = [row for row in rows if row["scenario_id"] == scenario["id"]]
        total = len(selected)
        correct = sum(row["correct"] for row in selected)
        false_acceptances = sum(row["false_acceptance"] for row in selected)
        false_rejections = sum(row["false_rejection"] for row in selected)
        low, high = wilson_interval(correct, total)
        latencies = [float(row["latency_ms"]) for row in selected]
        summaries.append(
            {
                "scenario_id": scenario["id"],
                "category": scenario["category"],
                "expected_decision": scenario["expected_decision"],
                "n": total,
                "correct": correct,
                "correct_rate": correct / total if total else 0.0,
                "correct_wilson_95_low": low,
                "correct_wilson_95_high": high,
                "false_acceptances": false_acceptances,
                "false_rejections": false_rejections,
                "latency_median_ms": statistics.median(latencies),
                "latency_p95_ms": percentile(latencies, 0.95),
            }
        )
    return summaries


def write_outputs(
    output: Path,
    manifest: Dict[str, Any],
    rows: List[Dict[str, Any]],
    summaries: List[Dict[str, Any]],
) -> None:
    output.mkdir(parents=True, exist_ok=False)
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output / "trials.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    with (output / "trials.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary_document = {"manifest": manifest, "summary": summaries}
    (output / "summary.json").write_text(
        json.dumps(summary_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Track A Functional Correctness: Verifier-Only Results",
        "",
        "These results exercise production canonicalization and authorization-state logic without claiming a real signing backend.",
        "",
        "| Scenario | Expected | n | Correct (95% Wilson CI) | False accept | False reject |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in summaries:
        lines.append(
            f"| {item['scenario_id']} | {item['expected_decision']} | {item['n']} | "
            f"{item['correct']}/{item['n']} ({item['correct_rate'] * 100:.2f}%, "
            f"{item['correct_wilson_95_low'] * 100:.2f}-{item['correct_wilson_95_high'] * 100:.2f}%) | "
            f"{item['false_acceptances']} | {item['false_rejections']} |"
        )
    (output / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260620)
    parser.add_argument("--run-id")
    parser.add_argument("--output-root", type=Path, default=ROOT / "experiments" / "track_a" / "raw")
    parser.add_argument("--allow-dirty", action="store_true", help="Diagnostic runs only; never publish as confirmatory")
    args = parser.parse_args()
    if args.trials < 1:
        raise SystemExit("--trials must be positive")
    dirty = bool(git(["status", "--porcelain"]))
    if dirty and not args.allow_dirty:
        raise SystemExit("refusing reportable run from a dirty relying-party repository")
    scenarios = load_scenarios()
    rng = random.Random(args.seed)
    rows = [
        execute_case(scenario, trial, rng)
        for scenario in scenarios
        for trial in range(1, args.trials + 1)
    ]
    summaries = summarize(rows, scenarios)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("functional-verifier-%Y%m%dT%H%M%SZ")
    output = args.output_root / run_id
    manifest = {
        "schema_version": "1.0.0",
        "experiment": "track_a_functional_correctness",
        "evidence_class": "verifier_only",
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials_per_scenario": args.trials,
        "random_seed": args.seed,
        "scenario_file": str(SCENARIOS_PATH.relative_to(ROOT)),
        "scenario_file_sha256": file_sha256(SCENARIOS_PATH),
        "rp_commit": git(["rev-parse", "HEAD"]),
        "rp_tree": git(["rev-parse", "HEAD^{tree}"]),
        "rp_dirty": dirty,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    write_outputs(output, manifest, rows, summaries)
    print(json.dumps({"run_id": run_id, "output": str(output), "trials": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
