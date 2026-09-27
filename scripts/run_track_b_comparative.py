#!/usr/bin/env python3
"""Run the preregistered Track B executable-baseline comparison."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.authorization_baselines import (
    AuthorizationRequest,
    MFAConfirmationGate,
    PoIAExactIntentGate,
    SessionOnlyGate,
    TransactionConfirmationGate,
)
from scripts.analyze_track_a import percentile, wilson_interval

SCENARIOS = ROOT / "experiments" / "track_b" / "scenarios" / "comparative_baselines.json"
CONFIGURATIONS = (
    "session_only",
    "mfa_confirmation",
    "transaction_confirmation",
    "poia_exact_intent",
)


def git(args: List[str]) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def gate_for(configuration: str):
    return {
        "session_only": SessionOnlyGate,
        "mfa_confirmation": MFAConfirmationGate,
        "transaction_confirmation": TransactionConfirmationGate,
        "poia_exact_intent": PoIAExactIntentGate,
    }[configuration]()


def approve(gate: Any, request: AuthorizationRequest, now: float) -> None:
    if isinstance(gate, MFAConfirmationGate):
        gate.approve(request.principal, now)
    elif hasattr(gate, "approve"):
        gate.approve(request)


def mutate(request: AuthorizationRequest, mutation: str) -> AuthorizationRequest:
    changed = copy.deepcopy(request)
    if mutation == "replace_rp":
        changed.context["rp_id"] = "attacker.example"
    elif mutation == "reuse_recent_confirmation":
        changed.context["session_id"] = "hijacked-session"
    elif mutation == "replace_amount":
        changed.scope["amount"] += 1
    elif mutation == "replace_action":
        changed = AuthorizationRequest(changed.principal, "api_key_rotate", changed.scope, changed.context)
    elif mutation == "replace_on_behalf_of":
        changed.context["on_behalf_of"] = "different-principal"
    elif mutation == "replace_workflow":
        changed.context["workflow_id"] = "different-workflow"
    elif mutation != "replay_consumed":
        raise ValueError(f"unsupported mutation: {mutation}")
    return changed


def run_attempt(configuration: str, scenario: Dict[str, str], attempt: int, rng: random.Random) -> Dict[str, Any]:
    base = AuthorizationRequest(
        principal=f"principal-{rng.randint(1, 25)}",
        action="transfer",
        scope={
            "amount": rng.randint(10, 10_000),
            "currency": "USD",
            "beneficiary_id": f"beneficiary-{rng.randint(1, 500)}",
        },
        context={
            "rp_id": "poia.local",
            "workflow_id": f"workflow-{attempt}",
            "on_behalf_of": "end-user",
            "session_id": "legitimate-session",
        },
    )
    gate = gate_for(configuration)
    now = 1_900_000_000.0 + attempt
    approve(gate, base, now)
    if scenario["mutation"] == "replay_consumed":
        gate.authorize(base, now)
        attacked = base
    else:
        attacked = mutate(base, scenario["mutation"])
    started = time.perf_counter_ns()
    accepted, reason = gate.authorize(attacked, now + 0.01)
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    return {
        "configuration": configuration,
        "scenario_id": scenario["id"],
        "attempt_n": attempt,
        "decision": "accept" if accepted else "reject",
        "attack_succeeded": accepted,
        "correct_rejection": not accepted,
        "rejection_reason": reason or "",
        "state_changed": accepted,
        "latency_ms": latency_ms,
    }


def run_control(configuration: str, attempt: int, rng: random.Random) -> Dict[str, Any]:
    request = AuthorizationRequest(
        principal=f"control-principal-{rng.randint(1, 25)}",
        action="transfer",
        scope={
            "amount": rng.randint(10, 10_000),
            "currency": "USD",
            "beneficiary_id": f"beneficiary-{rng.randint(1, 500)}",
        },
        context={
            "rp_id": "poia.local",
            "workflow_id": f"control-workflow-{attempt}",
            "on_behalf_of": "end-user",
            "session_id": "legitimate-session",
        },
    )
    gate = gate_for(configuration)
    now = 1_950_000_000.0 + attempt
    approve(gate, request, now)
    started = time.perf_counter_ns()
    accepted, reason = gate.authorize(request, now + 0.01)
    return {
        "configuration": configuration,
        "attempt_n": attempt,
        "decision": "accept" if accepted else "reject",
        "correct_acceptance": accepted,
        "false_rejection": not accepted,
        "rejection_reason": reason or "",
        "state_changed": accepted,
        "latency_ms": (time.perf_counter_ns() - started) / 1_000_000,
    }


def summarize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for configuration in CONFIGURATIONS:
        for scenario_id in sorted({row["scenario_id"] for row in rows}):
            selected = [
                row for row in rows
                if row["configuration"] == configuration and row["scenario_id"] == scenario_id
            ]
            successes = sum(bool(row["attack_succeeded"]) for row in selected)
            low, high = wilson_interval(successes, len(selected))
            latencies = [float(row["latency_ms"]) for row in selected]
            output.append(
                {
                    "configuration": configuration,
                    "scenario_id": scenario_id,
                    "n": len(selected),
                    "attack_successes": successes,
                    "attack_success_rate": successes / len(selected),
                    "wilson_95_low": low,
                    "wilson_95_high": high,
                    "latency_median_ms": statistics.median(latencies),
                    "latency_p95_ms": percentile(latencies, 0.95),
                    "latency_p99_ms": percentile(latencies, 0.99),
                }
            )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260620)
    parser.add_argument("--run-id")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    if args.trials != 200:
        raise SystemExit("Track B is preregistered at exactly 200 trials per cell")
    dirty = bool(git(["status", "--porcelain"]))
    if dirty and not args.allow_dirty:
        raise SystemExit("refusing reportable Track B run: repository is dirty")
    document = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    scenarios = document["scenarios"]
    rng = random.Random(args.seed)
    rows = [
        run_attempt(configuration, scenario, attempt, rng)
        for configuration in CONFIGURATIONS
        for scenario in scenarios
        for attempt in range(1, args.trials + 1)
    ]
    controls = [
        run_control(configuration, attempt, rng)
        for configuration in CONFIGURATIONS
        for attempt in range(1, args.trials + 1)
    ]
    summary = summarize(rows)
    control_summary = []
    for configuration in CONFIGURATIONS:
        selected = [row for row in controls if row["configuration"] == configuration]
        accepted = sum(bool(row["correct_acceptance"]) for row in selected)
        low, high = wilson_interval(accepted, len(selected))
        control_summary.append(
            {
                "configuration": configuration,
                "n": len(selected),
                "correct_acceptances": accepted,
                "false_rejections": len(selected) - accepted,
                "correct_acceptance_rate": accepted / len(selected),
                "wilson_95_low": low,
                "wilson_95_high": high,
            }
        )
    run_id = args.run_id or datetime.now(timezone.utc).strftime("track-b-%Y%m%dT%H%M%SZ")
    output = ROOT / "experiments" / "track_b" / "raw" / run_id
    output.mkdir(parents=True, exist_ok=False)
    manifest = {
        "experiment": "track_b",
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "commit": git(["rev-parse", "HEAD"]),
        "dirty": dirty,
        "reportable": not dirty,
        "seed": args.seed,
        "trials_per_cell": args.trials,
        "attack_observations": len(rows),
        "legitimate_control_observations": len(controls),
        "scenario_sha256": hashlib.sha256(SCENARIOS.read_bytes()).hexdigest(),
        "configurations": list(CONFIGURATIONS),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    with (output / "trials.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    with (output / "trials.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (output / "legitimate_controls.jsonl").open("w", encoding="utf-8") as handle:
        for row in controls:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    with (output / "legitimate_controls.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(controls[0]))
        writer.writeheader()
        writer.writerows(controls)
    (output / "summary.json").write_text(
        json.dumps({"attack_summary": summary, "control_summary": control_summary}, indent=2) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Track B Comparative Baseline Results", "",
        "| Configuration | Scenario | n | Attack success (95% Wilson CI) | P95 ms |",
        "|---|---|---:|---:|---:|",
    ]
    for item in summary:
        lines.append(
            f"| {item['configuration']} | {item['scenario_id']} | {item['n']} | "
            f"{item['attack_successes']}/{item['n']} "
            f"({item['attack_success_rate'] * 100:.2f}%, "
            f"{item['wilson_95_low'] * 100:.2f}-{item['wilson_95_high'] * 100:.2f}%) | "
            f"{item['latency_p95_ms']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Legitimate Controls",
            "",
            "| Configuration | n | Correct acceptance (95% Wilson CI) | False rejection |",
            "|---|---:|---:|---:|",
        ]
    )
    for item in control_summary:
        lines.append(
            f"| {item['configuration']} | {item['n']} | "
            f"{item['correct_acceptances']}/{item['n']} "
            f"({item['correct_acceptance_rate'] * 100:.2f}%, "
            f"{item['wilson_95_low'] * 100:.2f}-{item['wilson_95_high'] * 100:.2f}%) | "
            f"{item['false_rejections']} |"
        )
    (output / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"run_id={run_id}")
    print(f"output={output}")
    print(f"reportable={not dirty}")


if __name__ == "__main__":
    main()
