#!/usr/bin/env python3
"""Run manuscript RQ2 robustness and paired baseline-vs-PoIA attacks."""

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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "experiments" / "manuscript_20260824" / "scenarios" / "rq2_robustness.json"
OUTPUT_ROOT = ROOT / "experiments" / "manuscript_20260824" / "runs"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.authorization_baselines import AuthorizationRequest, SessionOnlyGate
from app.intent_codec import build_intent, canonical_json
from app.model import ChallengeRecord, InMemoryPoIA, IntentRecord, ProofRecord


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


def document() -> Dict[str, Any]:
    return json.loads(SCENARIOS.read_text(encoding="utf-8"))


def base_intent(trial: int, rng: random.Random, suffix: str = "") -> Dict[str, Any]:
    return build_intent(
        action="transfer",
        scope={
            "amount": rng.randint(100, 10_000),
            "currency": "USD",
            "target_resource": f"beneficiary-{trial}{suffix}",
            "tenant": "tenant-a",
            "risk_tier": "high",
        },
        context={
            "user_id": 7,
            "rp_id": "poia.local",
            "endpoint": "/execute-action",
            "session_id": f"session-{trial}",
            "device_id": "device-primary",
            "workflow_id": f"workflow-{trial}",
            "on_behalf_of": "self",
        },
    )


def fresh_store(intent: Dict[str, Any], trial: int, intent_id: str = "intent-1") -> Tuple[InMemoryPoIA, float]:
    created_at = 1_900_200_000.0 + trial * 100.0
    store = InMemoryPoIA()
    store.intents[intent_id] = IntentRecord(intent_id, intent, created_at)
    store.challenges[intent_id] = ChallengeRecord(intent_id, f"nonce-{intent_id}-{trial}", created_at + 60.0)
    store.proofs[intent_id] = ProofRecord(intent_id, "opaque-rq2-proof", "pending", "Pending", 0)
    ok, reason = store.approve_proof(ProofRecord(intent_id, "opaque-rq2-proof", "approved", "Approved", 0), created_at + 0.01)
    if not ok:
        raise RuntimeError(f"fixture approval failed: {reason}")
    return store, created_at


def request_from_intent(intent: Mapping[str, Any]) -> AuthorizationRequest:
    context = dict(intent["context"])
    principal = str(context.pop("user_id"))
    return AuthorizationRequest(
        principal=principal,
        action=str(intent["action"]),
        scope=dict(intent["scope"]),
        context=context,
    )


def mutate(intent: Dict[str, Any], mutation: str, trial: int) -> Dict[str, Any]:
    requested = copy.deepcopy(intent)
    if mutation in {"replay", "immediate_replay", "delayed_replay", "expired_replay", "consume_twice"}:
        return requested
    if mutation in {"relay_scope_change", "tamper_scope", "post_proof_mutation"}:
        requested["scope"]["amount"] += 999
    elif mutation == "missing_proof":
        return requested
    elif mutation in {"cross_action_reuse"}:
        requested["action"] = "delete-resource"
    elif mutation == "delegation_change":
        requested["context"]["on_behalf_of"] = "service-account"
    elif mutation == "other_session":
        requested["context"]["session_id"] = f"attacker-session-{trial}"
    elif mutation == "other_endpoint":
        requested["context"]["endpoint"] = "/admin/execute-action"
    elif mutation == "other_rp":
        requested["context"]["rp_id"] = "attacker.local"
    elif mutation == "other_tenant":
        requested["scope"]["tenant"] = "tenant-b"
    elif mutation == "other_device":
        requested["context"]["device_id"] = "device-secondary"
    elif mutation == "other_workflow":
        requested["context"]["workflow_id"] = f"workflow-other-{trial}"
    else:
        raise ValueError(f"unsupported mutation {mutation}")
    return requested


def poia_attack_decision(mutation: str, trial: int, rng: random.Random) -> Dict[str, Any]:
    intent = base_intent(trial, rng)
    requested = mutate(intent, mutation, trial)
    if mutation == "missing_proof":
        store = InMemoryPoIA()
        created_at = 1_900_200_000.0 + trial * 100.0
        store.intents["intent-1"] = IntentRecord("intent-1", intent, created_at)
        store.challenges["intent-1"] = ChallengeRecord("intent-1", f"nonce-{trial}", created_at + 60.0)
    else:
        store, created_at = fresh_store(intent, trial)

    if mutation in {"replay", "immediate_replay", "delayed_replay", "expired_replay", "consume_twice"}:
        ok, reason, _, _ = store.reserve_execution("intent-1", 7, created_at + 10.0, intent)
        if not ok:
            raise RuntimeError(f"setup execution failed: {reason}")
        now = created_at + 10.01
        if mutation == "delayed_replay":
            now = created_at + 40.0
        elif mutation == "expired_replay":
            now = created_at + 61.0
    else:
        now = created_at + 10.0

    start = time.perf_counter_ns()
    accepted, reason, _, _ = store.reserve_execution("intent-1", 7, now, requested)
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    return {
        "accepted": accepted,
        "reason": "" if accepted else reason,
        "latency_ms": latency_ms,
        "intent_sha256": hashlib.sha256(canonical_json(intent)).hexdigest(),
        "requested_intent_sha256": hashlib.sha256(canonical_json(requested)).hexdigest(),
    }


def baseline_decision(mutation: str, trial: int, rng: random.Random) -> bool:
    intent = mutate(base_intent(trial, rng), mutation, trial)
    gate = SessionOnlyGate()
    accepted, _ = gate.authorize(request_from_intent(intent), 1_900_200_000.0 + trial)
    return accepted


def concurrent_permutation(trial: int, rng: random.Random) -> Dict[str, Any]:
    intent_1 = base_intent(trial, rng, "-a")
    intent_2 = base_intent(trial, rng, "-b")
    store, created_at = fresh_store(intent_1, trial, "intent-1")
    store.intents["intent-2"] = IntentRecord("intent-2", intent_2, created_at)
    store.challenges["intent-2"] = ChallengeRecord("intent-2", f"nonce-intent-2-{trial}", created_at + 60.0)
    store.proofs["intent-2"] = ProofRecord("intent-2", "opaque-rq2-proof-2", "pending", "Pending", 0)
    ok, reason = store.approve_proof(ProofRecord("intent-2", "opaque-rq2-proof-2", "approved", "Approved", 0), created_at + 0.02)
    if not ok:
        raise RuntimeError(f"second approval failed: {reason}")
    start = time.perf_counter_ns()
    accepted, reason, _, _ = store.reserve_execution("intent-1", 7, created_at + 10.0, intent_2)
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    return {"accepted": accepted, "reason": "" if accepted else reason, "latency_ms": latency_ms}


def concurrent_race(trial: int, rng: random.Random) -> Dict[str, Any]:
    intent = base_intent(trial, rng)
    store, created_at = fresh_store(intent, trial)

    def attempt() -> Tuple[bool, str]:
        accepted, reason, _, _ = store.reserve_execution("intent-1", 7, created_at + 10.0, intent)
        return accepted, reason

    start = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda _: attempt(), range(10)))
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    successes = sum(accepted for accepted, _ in results)
    adversarial_successes = max(0, successes - 1)
    reasons = [reason for accepted, reason in results if not accepted]
    return {
        "accepted": adversarial_successes > 0,
        "reason": "" if adversarial_successes else (statistics.mode(reasons) if reasons else "proof_consumed"),
        "latency_ms": latency_ms,
        "race_successes": successes,
    }


def run_attack_outcomes(trials: int, rng: random.Random) -> List[Dict[str, Any]]:
    rows = []
    for scenario in document()["attack_outcomes"]:
        for trial in range(1, trials + 1):
            baseline_ok = baseline_decision(scenario["mutation"], trial, rng)
            poia = poia_attack_decision(scenario["mutation"], trial, rng)
            rows.append({
                "table": "attack_outcomes",
                "scenario_id": scenario["id"],
                "label": scenario["label"],
                "trial": trial,
                "baseline_success": baseline_ok,
                "poia_success": poia["accepted"],
                "poia_rejection_reason": poia["reason"],
                "poia_latency_ms": poia["latency_ms"],
                "intent_sha256": poia["intent_sha256"],
                "requested_intent_sha256": poia["requested_intent_sha256"],
            })
    return rows


def run_robustness(trials: int, rng: random.Random) -> List[Dict[str, Any]]:
    rows = []
    for attack_class in document()["robustness_classes"]:
        for mutation in attack_class["mutations"]:
            for trial in range(1, trials + 1):
                if mutation == "swap_intents":
                    result = concurrent_permutation(trial, rng)
                elif mutation == "consume_twice":
                    result = concurrent_race(trial, rng)
                else:
                    result = poia_attack_decision(mutation, trial, rng)
                rows.append({
                    "table": "robustness",
                    "attack_class": attack_class["label"],
                    "mutation": mutation,
                    "trial": trial,
                    "accepted": result["accepted"],
                    "rejection_reason": result["reason"],
                    "latency_ms": result["latency_ms"],
                })
    return rows


def grouped(rows: Iterable[Dict[str, Any]], key: str, accepted_key: str) -> List[Dict[str, Any]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row[key]), []).append(row)
    out = []
    for name in sorted(groups):
        selected = groups[name]
        latencies = [float(row.get("latency_ms", row.get("poia_latency_ms", 0.0))) for row in selected]
        successes = sum(bool(row[accepted_key]) for row in selected)
        reasons: Dict[str, int] = {}
        for row in selected:
            reason = str(row.get("rejection_reason") or row.get("poia_rejection_reason") or "accepted")
            reasons[reason] = reasons.get(reason, 0) + 1
        out.append({
            key: name,
            "attempts": len(selected),
            "accepted": successes,
            "asr": successes / len(selected),
            "median_latency_ms": statistics.median(latencies),
            "p95_latency_ms": percentile(latencies, 0.95),
            "dominant_reason": max(reasons, key=reasons.get),
        })
    return out


def summarize(attack_rows: List[Dict[str, Any]], robustness_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    baseline_successes = sum(row["baseline_success"] for row in attack_rows)
    poia_successes = sum(row["poia_success"] for row in attack_rows)
    robustness_successes = sum(row["accepted"] for row in robustness_rows)
    return {
        "attack_outcomes": {
            "attempts": len(attack_rows),
            "baseline_successes": baseline_successes,
            "baseline_asr": baseline_successes / len(attack_rows),
            "poia_successes": poia_successes,
            "poia_asr": poia_successes / len(attack_rows),
            "by_scenario": grouped(attack_rows, "label", "poia_success"),
        },
        "robustness": {
            "attempts": len(robustness_rows),
            "accepted": robustness_successes,
            "asr": robustness_successes / len(robustness_rows),
            "by_class": grouped(robustness_rows, "attack_class", "accepted"),
        },
    }


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_run(run_dir: Path, manifest: Dict[str, Any], attack_rows: List[Dict[str, Any]], robustness_rows: List[Dict[str, Any]]) -> None:
    raw = run_dir / "raw"
    analysis = run_dir / "analysis"
    tables = run_dir / "tables"
    raw.mkdir(parents=True, exist_ok=False)
    analysis.mkdir()
    tables.mkdir()
    write_csv(raw / "attack_outcomes.csv", attack_rows)
    write_csv(raw / "robustness.csv", robustness_rows)
    (raw / "attack_outcomes.jsonl").write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in attack_rows) + "\n", encoding="utf-8")
    (raw / "robustness.jsonl").write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in robustness_rows) + "\n", encoding="utf-8")
    summary = {**manifest, "summary": summarize(attack_rows, robustness_rows)}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (analysis / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# RQ2 Robustness", "", "## Paired Attack Outcomes", "", "| Scenario | Attempts | Baseline successes | PoIA successes | PoIA ASR |", "|---|---:|---:|---:|---:|"]
    by_label = {item["label"]: item for item in document()["attack_outcomes"]}
    for item in summary["summary"]["attack_outcomes"]["by_scenario"]:
        attempts = item["attempts"]
        lines.append(f"| {item['label']} | {attempts} | {attempts} | {item['accepted']} | {item['asr'] * 100:.3f}% |")
    lines.extend(["", "## Robustness Classes", "", "| Attack class | Attempts | Accepted | ASR | Dominant reason | Median latency (ms) |", "|---|---:|---:|---:|---|---:|"])
    for item in summary["summary"]["robustness"]["by_class"]:
        lines.append(f"| {item['attack_class']} | {item['attempts']} | {item['accepted']} | {item['asr'] * 100:.3f}% | {item['dominant_reason']} | {item['median_latency_ms']:.6f} |")
    (tables / "rq2_robustness.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    paths = [run_dir / "manifest.json", raw / "attack_outcomes.csv", raw / "robustness.csv", raw / "attack_outcomes.jsonl", raw / "robustness.jsonl", analysis / "summary.json", tables / "rq2_robustness.md"]
    (analysis / "checksums.sha256").write_text("\n".join(f"{sha256(path)}  {path.relative_to(run_dir)}" for path in sorted(paths)) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260824)
    parser.add_argument("--run-id", default="rq2-robustness-20260824")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    for _ in range(args.warmup):
        poia_attack_decision("replay", -1, rng)
    attack_rows = run_attack_outcomes(args.trials, rng)
    robustness_rows = run_robustness(args.trials, rng)
    manifest = {
        "schema_version": "1.0.0",
        "experiment": "RQ2_robustness",
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials_per_atomic_scenario": args.trials,
        "warmup_trials": args.warmup,
        "random_seed": args.seed,
        "scenario_file": str(SCENARIOS.relative_to(ROOT)),
        "scenario_file_sha256": sha256(SCENARIOS),
        "rp_commit": git(["rev-parse", "HEAD"]),
        "rp_tree": git(["rev-parse", "HEAD^{tree}"]),
        "rp_dirty": bool(git(["status", "--porcelain"])),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "evidence_class": "paired_session_baseline_and_poia_verifier_state_machine",
    }
    run_dir = OUTPUT_ROOT / args.run_id
    write_run(run_dir, manifest, attack_rows, robustness_rows)
    print(json.dumps({"run_id": args.run_id, "run_dir": str(run_dir), "attack_trials": len(attack_rows), "robustness_trials": len(robustness_rows)}, indent=2))


if __name__ == "__main__":
    main()
