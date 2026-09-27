#!/usr/bin/env python3
"""Manifest-bound PoIA cross-domain generality experiment."""

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
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.intent_codec import canonical_json  # noqa: E402
from app.model import intent_mismatch_reason  # noqa: E402

TRIALS = 200
CASES = (
    "exact_match",
    "action_substitution",
    "target_substitution",
    "value_substitution",
    "principal_substitution",
    "rp_substitution",
    "nonce_substitution",
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


def domain_schema(domain: str, trial: int) -> dict[str, Any]:
    common = {
        "context": {
            "rp_id": f"poia-{domain}",
            "user_id": f"principal-{trial % 31}",
            "workflow_id": f"workflow-{domain}-{trial}",
        },
        "constraints": {"nonce": f"nonce-{domain}-{trial}", "expires_in_seconds": 60},
    }
    schemas = {
        "banking": {
            "action": "transfer",
            "scope": {"from_account": f"account-{trial % 17}", "to_account": f"beneficiary-{trial % 23}", "amount": 100 + trial % 19, "currency": "USD"},
        },
        "enterprise": {
            "action": "grant_role",
            "scope": {"target_user": f"employee-{trial % 29}", "role": "reader", "tenant": f"tenant-{trial % 7}", "duration_hours": 4},
        },
        "healthcare": {
            "action": "export_record",
            "scope": {"patient_id": f"patient-{trial % 37}", "record_type": "lab_results", "recipient": f"clinic-{trial % 11}", "purpose": "referral"},
        },
        "cloud_api": {
            "action": "rotate_key",
            "scope": {"key_id": f"kms-key-{trial % 41}", "project": f"project-{trial % 13}", "region": "ap-northeast-1", "change_request": f"change-{trial}"},
        },
    }
    return {**schemas[domain], **common}


def changed(intent: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    result = deepcopy(intent)
    cursor: dict[str, Any] = result
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return result


def requested_case(domain: str, intent: dict[str, Any], case: str) -> tuple[dict[str, Any], str]:
    if case == "exact_match":
        return deepcopy(intent), "approved"
    if case == "action_substitution":
        return changed(intent, ("action",), "delete_resource"), "action_mismatch"
    if case == "principal_substitution":
        return changed(intent, ("context", "user_id"), "principal-substituted"), "principal_mismatch"
    if case == "rp_substitution":
        return changed(intent, ("context", "rp_id"), "poia-wrong-rp"), "rp_mismatch"
    if case == "nonce_substitution":
        return changed(intent, ("constraints", "nonce"), "nonce-substituted"), "constraints_mismatch"
    target_paths = {
        "banking": ("scope", "to_account"),
        "enterprise": ("scope", "target_user"),
        "healthcare": ("scope", "patient_id"),
        "cloud_api": ("scope", "key_id"),
    }
    value_paths = {
        "banking": (("scope", "amount"), 999999),
        "enterprise": (("scope", "role"), "administrator"),
        "healthcare": (("scope", "purpose"), "marketing"),
        "cloud_api": (("scope", "project"), "root-identity"),
    }
    if case == "target_substitution":
        return changed(intent, target_paths[domain], "target-substituted"), "scope_mismatch"
    path, value = value_paths[domain]
    return changed(intent, path, value), "scope_mismatch"


def verify(
    approved: dict[str, Any],
    requested: dict[str, Any],
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[bool, str, float]:
    started = time.perf_counter_ns()
    try:
        public_key.verify(signature, canonical_json(approved), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "invalid_signature", (time.perf_counter_ns() - started) / 1_000_000
    mismatch = intent_mismatch_reason(approved, requested)
    return mismatch is None, mismatch or "approved", (time.perf_counter_ns() - started) / 1_000_000


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_table(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"# Cross-Domain Generality: `{summary['run_id']}`",
        "",
        "| Domain | Decisions | Correct accept | Correct reject | False accept | False reject | Median ms | P95 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in summary["domains"]:
        lines.append(
            f"| {item['domain']} | {item['decisions']} | {item['correct_acceptances']} | "
            f"{item['correct_rejections']} | {item['false_acceptances']} | {item['false_rejections']} | "
            f"{item['latency']['median_ms']:.4f} | {item['latency']['p95_ms']:.4f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--trials", type=int, default=TRIALS)
    parser.add_argument("--out-dir", default="experiments/cross_domain_generality")
    args = parser.parse_args()
    if args.trials != TRIALS:
        raise SystemExit(f"confirmatory sample size is fixed at {TRIALS}")
    if git("status", "--porcelain"):
        raise SystemExit("cross-domain confirmatory runs require a clean working tree")

    out = ROOT / args.out_dir
    paths = {
        "manifest": out / f"{args.run_id}-manifest.json",
        "summary": out / f"{args.run_id}-summary.json",
        "table": out / f"{args.run_id}-table.md",
        "trials": out / f"{args.run_id}-trials.csv",
        "checksums": out / f"{args.run_id}-checksums.sha256",
    }
    if any(path.exists() for path in paths.values()):
        raise SystemExit(f"run ID already exists: {args.run_id}")

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    rows = []
    domains = []
    for domain in ("banking", "enterprise", "healthcare", "cloud_api"):
        domain_rows = []
        for trial in range(args.trials):
            approved = domain_schema(domain, trial)
            signature = private_key.sign(canonical_json(approved), ec.ECDSA(hashes.SHA256()))
            for case in CASES:
                requested, expected_reason = requested_case(domain, approved, case)
                accepted, reason, latency_ms = verify(approved, requested, signature, public_key)
                expected_accept = case == "exact_match"
                correct = accepted == expected_accept and reason == expected_reason
                row = {
                    "domain": domain,
                    "trial": trial,
                    "case": case,
                    "expected_accept": int(expected_accept),
                    "observed_accept": int(accepted),
                    "expected_reason": expected_reason,
                    "observed_reason": reason,
                    "correct": int(correct),
                    "verification_ms": latency_ms,
                }
                rows.append(row)
                domain_rows.append(row)
        false_accepts = sum(int(row["observed_accept"] and not row["expected_accept"]) for row in domain_rows)
        false_rejects = sum(int(not row["observed_accept"] and row["expected_accept"]) for row in domain_rows)
        if false_accepts or false_rejects or not all(row["correct"] for row in domain_rows):
            raise RuntimeError(f"invalid cross-domain result: {domain}")
        domains.append(
            {
                "domain": domain,
                "decisions": len(domain_rows),
                "correct_acceptances": sum(row["observed_accept"] for row in domain_rows),
                "correct_rejections": sum(1 - row["observed_accept"] for row in domain_rows),
                "false_acceptances": false_accepts,
                "false_rejections": false_rejects,
                "latency": latency_summary([row["verification_ms"] for row in domain_rows]),
            }
        )

    manifest = {
        "run_id": args.run_id,
        "repository_commit": git("rev-parse", "HEAD"),
        "tree_clean": True,
        "trials_per_case": args.trials,
        "domains": [item["domain"] for item in domains],
        "cases": list(CASES),
        "expected_decisions": 5600,
        "python_version": platform.python_version(),
        "runner_sha256": sha256_file(Path(__file__)),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "cross_domain_preregistration.md"),
        "private_key_persisted": False,
    }
    summary = {"run_id": args.run_id, "decisions": len(rows), "domains": domains}
    if len(rows) != 5600:
        raise RuntimeError("unexpected cross-domain decision count")
    write_json(paths["manifest"], manifest)
    write_json(paths["summary"], summary)
    write_csv(paths["trials"], rows)
    write_table(paths["table"], summary)
    artifacts = (Path(__file__), paths["manifest"], paths["summary"], paths["trials"], paths["table"])
    paths["checksums"].write_text(
        "\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in artifacts) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
