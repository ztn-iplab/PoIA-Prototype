#!/usr/bin/env python3
"""Run manuscript RQ3 cross-domain generalizability experiments."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "experiments" / "manuscript_20260824" / "scenarios" / "rq3_cross_domain.json"
OUTPUT_ROOT = ROOT / "experiments" / "manuscript_20260824" / "runs"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


def domain_intent(domain: str, trial: int, rng: random.Random) -> Dict[str, Any]:
    common_context = {
        "user_id": 7,
        "rp_id": "poia.local",
        "endpoint": "/execute-action",
        "session_id": f"session-{domain}-{trial}",
        "workflow_id": f"workflow-{domain}-{trial}",
        "tenant": "tenant-a",
    }
    if domain == "transactional":
        return build_intent("transfer", {
            "amount": rng.randint(100, 10_000),
            "currency": "USD",
            "beneficiary_id": f"beneficiary-{trial}",
            "source_account": "checking-1",
        }, common_context)
    if domain == "iam":
        return build_intent("grant-role", {
            "principal": f"user-{trial % 31}",
            "role": "auditor",
            "resource": "tenant-a/project-1",
            "permissions": ["read"],
        }, common_context)
    if domain == "cloud":
        return build_intent("delete-resource", {
            "resource_id": f"vm-{trial}",
            "project": "production",
            "region": "us-west1",
            "safety_window": "maintenance",
        }, common_context)
    if domain == "data_export":
        return build_intent("export-dataset", {
            "dataset_id": f"patient-cohort-{trial}",
            "recipient": "research-partner-a",
            "fields": ["age", "diagnosis", "treatment"],
            "purpose": "approved-study",
        }, common_context)
    raise ValueError(f"unknown domain {domain}")


def mutate(intent: Dict[str, Any], mutation: str, trial: int) -> Dict[str, Any]:
    requested = copy.deepcopy(intent)
    if mutation == "action":
        requested["action"] = f"{requested['action']}-other"
    elif mutation == "target":
        first_key = next(iter(requested["scope"]))
        requested["scope"][first_key] = f"other-target-{trial}"
    elif mutation == "scope":
        requested["scope"]["extra_privilege"] = "export"
    elif mutation == "context":
        requested["context"]["tenant"] = "tenant-b"
    elif mutation == "replay":
        pass
    else:
        raise ValueError(f"unknown mutation {mutation}")
    return requested


def fresh_store(intent: Dict[str, Any], trial: int) -> Tuple[InMemoryPoIA, float]:
    created_at = 1_900_300_000.0 + trial * 100.0
    store = InMemoryPoIA()
    store.intents["intent-1"] = IntentRecord("intent-1", intent, created_at)
    store.challenges["intent-1"] = ChallengeRecord("intent-1", f"nonce-{trial}", created_at + 60.0)
    store.proofs["intent-1"] = ProofRecord("intent-1", "opaque-rq3-proof", "pending", "Pending", 0)
    ok, reason = store.approve_proof(ProofRecord("intent-1", "opaque-rq3-proof", "approved", "Approved", 0), created_at + 0.01)
    if not ok:
        raise RuntimeError(f"approval failed: {reason}")
    return store, created_at


def execute(domain: str, mutation: str, trial: int, rng: random.Random) -> Dict[str, Any]:
    intent = domain_intent(domain, trial, rng)
    requested = mutate(intent, mutation, trial) if mutation != "valid" else copy.deepcopy(intent)
    store, created_at = fresh_store(intent, trial)
    if mutation == "replay":
        ok, reason, _, _ = store.reserve_execution("intent-1", 7, created_at + 10.0, intent)
        if not ok:
            raise RuntimeError(f"setup replay execution failed: {reason}")
    start = time.perf_counter_ns()
    accepted, reason, _, _ = store.reserve_execution("intent-1", 7, created_at + 10.1, requested)
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    expected_accept = mutation == "valid"
    return {
        "domain": domain,
        "mutation": mutation,
        "trial": trial,
        "expected_decision": "accept" if expected_accept else "reject",
        "decision": "accept" if accepted else "reject",
        "correct": accepted == expected_accept,
        "false_acceptance": mutation != "valid" and accepted,
        "false_rejection": mutation == "valid" and not accepted,
        "rejection_reason": "" if accepted else reason,
        "latency_ms": latency_ms,
        "canonical_intent_bytes": len(canonical_json(intent)),
        "intent_sha256": hashlib.sha256(canonical_json(intent)).hexdigest(),
        "requested_intent_sha256": hashlib.sha256(canonical_json(requested)).hexdigest(),
    }


def grouped(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    labels = {item["id"]: item for item in document()["domains"]}
    for domain in [item["id"] for item in document()["domains"]]:
        selected = [row for row in rows if row["domain"] == domain]
        valid = [row for row in selected if row["mutation"] == "valid"]
        mutated = [row for row in selected if row["mutation"] != "valid"]
        latencies = [float(row["latency_ms"]) for row in selected]
        out.append({
            "domain": domain,
            "label": labels[domain]["label"],
            "operation": labels[domain]["operation"],
            "valid_cases": len(valid),
            "valid_rejections": sum(row["false_rejection"] for row in valid),
            "frr": sum(row["false_rejection"] for row in valid) / len(valid),
            "mutation_cases": len(mutated),
            "mutation_acceptances": sum(row["false_acceptance"] for row in mutated),
            "far": sum(row["false_acceptance"] for row in mutated) / len(mutated),
            "median_latency_ms": statistics.median(latencies),
            "p95_latency_ms": percentile(latencies, 0.95),
            "median_intent_bytes": statistics.median([row["canonical_intent_bytes"] for row in selected]),
        })
    return out


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_domain = grouped(rows)
    valid = [row for row in rows if row["mutation"] == "valid"]
    mutated = [row for row in rows if row["mutation"] != "valid"]
    medians = [item["median_latency_ms"] for item in by_domain]
    return {
        "total_valid_requests": len(valid),
        "total_semantic_mutations": len(mutated),
        "cross_domain_frr": sum(row["false_rejection"] for row in valid) / len(valid),
        "cross_domain_far": sum(row["false_acceptance"] for row in mutated) / len(mutated),
        "minimum_median_latency_ms": min(medians),
        "maximum_median_latency_ms": max(medians),
        "latency_interpretation": "schema complexity did not materially affect verifier decisions in this verifier-only run",
        "by_domain": by_domain,
    }


def write_run(run_dir: Path, manifest: Dict[str, Any], rows: List[Dict[str, Any]]) -> None:
    raw = run_dir / "raw"
    analysis = run_dir / "analysis"
    tables = run_dir / "tables"
    raw.mkdir(parents=True, exist_ok=False)
    analysis.mkdir()
    tables.mkdir()
    with (raw / "trials.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (raw / "trials.jsonl").write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) + "\n", encoding="utf-8")
    summary = {**manifest, "summary": summarize(rows)}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (analysis / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# RQ3 Cross-Domain Generalizability", "", "| Domain | Valid cases | FRR | Mutation cases | FAR | Median latency (ms) |", "|---|---:|---:|---:|---:|---:|"]
    for item in summary["summary"]["by_domain"]:
        lines.append(f"| {item['label']} | {item['valid_cases']} | {item['frr'] * 100:.3f}% | {item['mutation_cases']} | {item['far'] * 100:.3f}% | {item['median_latency_ms']:.6f} |")
    (tables / "rq3_cross_domain.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    paths = [run_dir / "manifest.json", raw / "trials.csv", raw / "trials.jsonl", analysis / "summary.json", tables / "rq3_cross_domain.md"]
    (analysis / "checksums.sha256").write_text("\n".join(f"{sha256(path)}  {path.relative_to(run_dir)}" for path in sorted(paths)) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260824)
    parser.add_argument("--run-id", default="rq3-cross-domain-20260824")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    domains = [item["id"] for item in document()["domains"]]
    mutations = ["valid", *document()["mutations"]]
    for _ in range(args.warmup):
        execute(domains[0], "valid", -1, rng)
    rows = [execute(domain, mutation, trial, rng) for domain in domains for mutation in mutations for trial in range(1, args.trials + 1)]
    manifest = {
        "schema_version": "1.0.0",
        "experiment": "RQ3_cross_domain",
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials_per_domain_condition": args.trials,
        "warmup_trials": args.warmup,
        "random_seed": args.seed,
        "scenario_file": str(SCENARIOS.relative_to(ROOT)),
        "scenario_file_sha256": sha256(SCENARIOS),
        "rp_commit": git(["rev-parse", "HEAD"]),
        "rp_tree": git(["rev-parse", "HEAD^{tree}"]),
        "rp_dirty": bool(git(["status", "--porcelain"])),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "evidence_class": "same_verifier_with_domain_specific_intent_schemas",
    }
    run_dir = OUTPUT_ROOT / args.run_id
    write_run(run_dir, manifest, rows)
    print(json.dumps({"run_id": args.run_id, "run_dir": str(run_dir), "trials": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
