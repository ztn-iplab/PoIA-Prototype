#!/usr/bin/env python3
"""Unit-level referent and consistency-check harness.

This calls real helper functions but obtains no signatures and executes no
protected operations. Counts describe deterministic fixtures, not live attack
success rates. The disabled gate returns success without simulating an executor.
Latency is helper-call duration, not end-to-end or incremental authorization cost.
Results must not be used as evidence of independent-root compromise resilience.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, List


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_referent_substitution(trials: int) -> Dict[str, Any]:
    from app import db as db_module
    from app import core as core_module

    rows: List[Dict[str, Any]] = []
    legacy_accepted_on_mutated = 0
    strengthened_rejected = 0
    latencies_ms: List[float] = []
    rejection_reasons: Dict[str, int] = {}

    with db_module.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            (f"rq7-referent-{os.getpid()}@example.invalid", "unused", int(time.time())),
        ).lastrowid

    for i in range(trials):
        with db_module.db_connect() as conn:
            beneficiary_id = conn.execute(
                "INSERT INTO beneficiaries (user_id, name, bank, account_number, version, updated_at, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                (user_id, f"Trial Beneficiary {i}", "Origin Bank", f"{100000 + i}", int(time.time()), int(time.time())),
            ).lastrowid

        # Commit: build the intent, snapshotting the beneficiary's content hash
        # exactly as create_poia_intent does in production (RSI_ENABLED does not
        # gate the snapshot step -- only whether it is re-checked at execution).
        scope = {"from_account": 0, "amount": 10.0, "currency": "USD", "beneficiary_id": beneficiary_id}
        context: Dict[str, Any] = {"rp_id": "poia-demo-bank", "user_id": user_id}
        referent_commitments = core_module.compute_referent_commitments("transfer", scope)
        context = dict(context)
        if referent_commitments:
            context["referent_commitments"] = referent_commitments
        intent_body = {"action": "transfer", "scope": scope, "context": context}

        # Mutate the referent after commit, before execution -- the attack.
        with db_module.db_connect() as conn:
            conn.execute(
                "UPDATE beneficiaries SET account_number = ?, version = version + 1 WHERE id = ?",
                (f"MUTATED-{i}", beneficiary_id),
            )

        # Strengthened gate.
        core_module.RSI_ENABLED = True
        started = time.perf_counter()
        strengthened_reason = core_module.verify_referent_commitments(intent_body)
        latencies_ms.append((time.perf_counter() - started) * 1000.0)
        if strengthened_reason:
            strengthened_rejected += 1
            rejection_reasons[strengthened_reason] = rejection_reasons.get(strengthened_reason, 0) + 1

        # Legacy gate (same fixture, same mutated content).
        core_module.RSI_ENABLED = False
        legacy_reason = core_module.verify_referent_commitments(intent_body)
        if legacy_reason is None:
            legacy_accepted_on_mutated += 1
        core_module.RSI_ENABLED = True

        rows.append(
            {
                "trial": i,
                "beneficiary_id": beneficiary_id,
                "legacy_decision": "accept" if legacy_reason is None else "reject",
                "legacy_reason": legacy_reason or "",
                "strengthened_decision": "accept" if strengthened_reason is None else "reject",
                "strengthened_reason": strengthened_reason or "",
                "check_latency_ms": latencies_ms[-1],
            }
        )

    dominant_reason = max(rejection_reasons, key=rejection_reasons.get) if rejection_reasons else "n/a"
    return {
        "attempts": trials,
        "legacy_gate_acceptance_rate_on_mutated_referent": legacy_accepted_on_mutated / trials,
        "strengthened_gate_rejection_rate": strengthened_rejected / trials,
        "dominant_rejection_reason": dominant_reason,
        "median_check_latency_ms": sorted(latencies_ms)[len(latencies_ms) // 2],
        "rows": rows,
    }


def run_commitment_root_compromise(trials: int) -> Dict[str, Any]:
    from app import commitment_confinement as cc_module

    rows: List[Dict[str, Any]] = []
    coincide_count = 0
    k1_accepted_adversarial = 0
    k2_rejected = 0
    k2_latencies_ms = []

    action = "limit_change"
    scope = {"account_id": 1, "new_daily_limit": 5000.0}
    context = {"rp_id": "poia-demo-bank"}

    cc_module.POIA_EXPERIMENT_MODE = True
    try:
        for i in range(trials):
            true_value = cc_module._root_b_canonical(action, scope, context)
            coincide = random.random() < 0.5
            if coincide:
                adversarial_value = true_value
                coincide_count += 1
            else:
                adversarial_value = dict(true_value)
                adversarial_value["new_daily_limit"] = "999999.00"  # a substituted, unapproved limit

            os.environ["POIA_SIMULATE_COMPROMISE_ROOT_A"] = action
            os.environ["POIA_SIMULATE_COMPROMISE_ROOT_A_VALUE"] = json.dumps(adversarial_value)
            try:
                cc_module.KOFN_ENABLED = False
                k1_reason = cc_module.confine_commitment(action=action, scope=scope, context=context)
                if k1_reason is None:
                    k1_accepted_adversarial += 1

                cc_module.KOFN_ENABLED = True
                started = time.perf_counter()
                k2_reason = cc_module.confine_commitment(action=action, scope=scope, context=context)
                k2_latencies_ms.append((time.perf_counter() - started) * 1000.0)
                if k2_reason is not None:
                    k2_rejected += 1
            finally:
                os.environ.pop("POIA_SIMULATE_COMPROMISE_ROOT_A", None)
                os.environ.pop("POIA_SIMULATE_COMPROMISE_ROOT_A_VALUE", None)

            rows.append(
                {
                    "trial": i,
                    "adversarial_value_coincided_with_honest_report": coincide,
                    "k1_legacy_decision": "accept" if k1_reason is None else "reject",
                    "k2_strengthened_decision": "accept" if k2_reason is None else "reject",
                }
            )
    finally:
        cc_module.POIA_EXPERIMENT_MODE = False
        cc_module.KOFN_ENABLED = True

    return {
        "attempts": trials,
        "k1_legacy_gate_acceptance_rate_of_adversarial_value": k1_accepted_adversarial / trials,
        "k2_strengthened_gate_rejection_rate": k2_rejected / trials,
        "fraction_trials_compromised_value_coincided_with_honest_report": coincide_count / trials,
        "median_decision_latency_ms": sorted(k2_latencies_ms)[len(k2_latencies_ms) // 2],
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run helper-level checks; not signed end-to-end attack experiments.")
    parser.add_argument("--trials", type=int, default=300)
    parser.add_argument("--out-dir", type=str, default="experiments/lifecycle_resilience")
    parser.add_argument("--seed", type=int, default=20260906)
    args = parser.parse_args()

    random.seed(args.seed)

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        from app import db as db_module
        from app import poia_metrics

        db_module.DB_PATH = Path(tmp) / "bank.db"
        poia_metrics.METRICS_CSV = Path(tmp) / "metrics.csv"
        db_module.init_db()

        referent_result = run_referent_substitution(args.trials)
        compromise_result = run_commitment_root_compromise(args.trials)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "evidence_kind": "unit_checks_not_live_signed_executions",
        "referent_substitution": {k: v for k, v in referent_result.items() if k != "rows"},
        "commitment_root_compromise": {k: v for k, v in compromise_result.items() if k != "rows"},
        "trials_per_family": args.trials,
        "seed": args.seed,
    }
    write_json(out_dir / "lifecycle_resilience_summary.json", summary)
    write_csv(out_dir / "lifecycle_resilience_referent_substitution_trials.csv", referent_result["rows"])
    write_csv(out_dir / "lifecycle_resilience_commitment_compromise_trials.csv", compromise_result["rows"])

    table_lines = [
        "| Attack family | Attempts | Legacy accepts attack | Strengthened rejects attack | Dominant reason |",
        "|---|---:|---:|---:|---|",
        (
            f"| Referent substitution after commit | {referent_result['attempts']} | "
            f"{referent_result['legacy_gate_acceptance_rate_on_mutated_referent']:.1%} | "
            f"{referent_result['strengthened_gate_rejection_rate']:.1%} | "
            f"{referent_result['dominant_rejection_reason']} |"
        ),
        (
            f"| Commitment-root compromise | {compromise_result['attempts']} | "
            f"{compromise_result['k1_legacy_gate_acceptance_rate_of_adversarial_value']:.1%} | "
            f"{compromise_result['k2_strengthened_gate_rejection_rate']:.1%} | "
            f"commitment_root_disagreement | {compromise_result['median_decision_latency_ms']:.4f} ms |"
        ),
        "",
        f"Median RSI helper-call duration: {referent_result['median_check_latency_ms']:.4f} ms (not incremental latency).",
        (
            "Fraction of commitment-root-compromise trials where the adversarial value coincided "
            f"with the honest report: {compromise_result['fraction_trials_compromised_value_coincided_with_honest_report']:.1%}."
        ),
    ]
    (out_dir / "lifecycle_resilience_table.md").write_text("\n".join(table_lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"\nArtifacts written to: {out_dir}")


if __name__ == "__main__":
    main()
