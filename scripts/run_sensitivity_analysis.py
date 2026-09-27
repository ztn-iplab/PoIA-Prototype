#!/usr/bin/env python3
"""Manifest-bound PoIA parameter sensitivity analysis."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.intent_codec import canonical_json  # noqa: E402

TTLS = (30, 60, 120)
DELAYS = (0, 29, 30, 31, 59, 60, 61, 119, 120, 121, 150)
PARAMETER_COUNTS = (5, 20, 50, 100)
COMPLEXITIES = ("flat", "nested")
CONCURRENCIES = (1, 10, 50, 100)
COMPUTE_SAMPLES = 200
CONCURRENCY_OPERATIONS = 500


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_intent(parameter_count: int, complexity: str) -> dict[str, Any]:
    values = {f"field_{index:03d}": f"value-{index:03d}" for index in range(parameter_count)}
    if complexity == "flat":
        scope: dict[str, Any] = values
    elif complexity == "nested":
        scope = {"groups": []}
        group_size = max(1, math.ceil(parameter_count / 5))
        items = list(values.items())
        for start in range(0, parameter_count, group_size):
            scope["groups"].append({"values": dict(items[start : start + group_size])})
    else:
        raise ValueError(f"unsupported complexity: {complexity}")
    return {
        "action": "sensitivity_action",
        "scope": scope,
        "context": {
            "rp_id": "poia.local",
            "user_id": "sensitivity-user",
            "workflow_id": "sensitivity-workflow",
        },
        "constraints": {"nonce": "sensitivity-nonce", "expires_in_seconds": 60},
    }


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def describe(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "mean": statistics.mean(values),
    }


def measure_operation(
    intent: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
) -> dict[str, float | int | bool]:
    operation_start = time.perf_counter_ns()
    start = time.perf_counter_ns()
    payload = canonical_json(intent)
    canonicalization_us = (time.perf_counter_ns() - start) / 1_000

    start = time.perf_counter_ns()
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    signature_us = (time.perf_counter_ns() - start) / 1_000

    start = time.perf_counter_ns()
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    verification_us = (time.perf_counter_ns() - start) / 1_000
    operation_us = (time.perf_counter_ns() - operation_start) / 1_000
    return {
        "intent_bytes": len(payload),
        "canonicalization_us": canonicalization_us,
        "signature_us": signature_us,
        "verification_us": verification_us,
        "operation_us": operation_us,
        "verified": True,
    }


def expiry_matrix() -> list[dict[str, Any]]:
    rows = []
    for ttl in TTLS:
        for delay in DELAYS:
            accepted = delay <= ttl
            rows.append(
                {
                    "ttl_s": ttl,
                    "modeled_arrival_delay_s": delay,
                    "accepted": int(accepted),
                    "policy_rejection": int(not accepted),
                    "false_rejection": int(delay <= ttl and not accepted),
                    "replay_exposure_upper_bound_s": ttl,
                    "boundary_relation": "before" if delay < ttl else "at" if delay == ttl else "after",
                }
            )
    return rows


def compute_matrix() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    rows = []
    summaries = []
    for parameter_count in PARAMETER_COUNTS:
        for complexity in COMPLEXITIES:
            intent = build_intent(parameter_count, complexity)
            cell = []
            for sample in range(COMPUTE_SAMPLES):
                result = measure_operation(intent, private_key, public_key)
                row = {"parameter_count": parameter_count, "complexity": complexity, "sample": sample, **result}
                rows.append(row)
                cell.append(row)
            summaries.append(
                {
                    "parameter_count": parameter_count,
                    "complexity": complexity,
                    "samples": len(cell),
                    "intent_bytes": cell[0]["intent_bytes"],
                    "canonicalization_us": describe([float(row["canonicalization_us"]) for row in cell]),
                    "signature_us": describe([float(row["signature_us"]) for row in cell]),
                    "verification_us": describe([float(row["verification_us"]) for row in cell]),
                    "operation_us": describe([float(row["operation_us"]) for row in cell]),
                    "verification_failures": sum(not bool(row["verified"]) for row in cell),
                }
            )
    return rows, summaries


def concurrency_matrix() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    intent = build_intent(20, "nested")
    rows = []
    summaries = []
    for workers in CONCURRENCIES:
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            cell = list(
                executor.map(
                    lambda _: measure_operation(intent, private_key, public_key),
                    range(CONCURRENCY_OPERATIONS),
                )
            )
        wall_s = time.perf_counter() - start
        for operation, result in enumerate(cell):
            rows.append({"workers": workers, "operation": operation, **result})
        summaries.append(
            {
                "workers": workers,
                "operations": len(cell),
                "wall_seconds": wall_s,
                "throughput_ops_per_second": len(cell) / wall_s,
                "operation_us": describe([float(row["operation_us"]) for row in cell]),
                "verification_failures": sum(not bool(row["verified"]) for row in cell),
            }
        )
    return rows, summaries


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(materialized[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(materialized)


def write_table(path: Path, compute: list[dict[str, Any]], concurrency: list[dict[str, Any]]) -> None:
    lines = [
        "# PoIA Sensitivity Analysis",
        "",
        "## Intent Complexity",
        "",
        "| Parameters | Shape | Bytes | Canonicalize median/p95 (us) | Sign median/p95 (us) | Verify median/p95 (us) | Operation median/p95 (us) |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    for row in compute:
        metric = lambda name: f"{row[name]['median']:.2f}/{row[name]['p95']:.2f}"
        lines.append(f"| {row['parameter_count']} | {row['complexity']} | {row['intent_bytes']} | {metric('canonicalization_us')} | {metric('signature_us')} | {metric('verification_us')} | {metric('operation_us')} |")
    lines.extend(["", "## Concurrency", "", "| Workers | Operations | Throughput (ops/s) | Operation median/p95 (us) | Failures |", "|---:|---:|---:|---:|---:|"])
    for row in concurrency:
        lines.append(f"| {row['workers']} | {row['operations']} | {row['throughput_ops_per_second']:.2f} | {row['operation_us']['median']:.2f}/{row['operation_us']['p95']:.2f} | {row['verification_failures']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", default="experiments/sensitivity_analysis")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        raise SystemExit("sensitivity analysis requires a clean tree")

    out = ROOT / args.out_dir
    suffixes = {
        "expiry": "expiry-policy.csv",
        "compute_raw": "compute-raw.csv",
        "concurrency_raw": "concurrency-raw.csv",
        "summary": "summary.json",
        "table": "table.md",
        "manifest": "manifest.json",
        "checksums": "checksums.sha256",
    }
    paths = {name: out / f"{args.run_id}-{suffix}" for name, suffix in suffixes.items()}
    if any(path.exists() for path in paths.values()):
        raise SystemExit(f"run ID already exists: {args.run_id}")

    expiry = expiry_matrix()
    compute_raw, compute_summary = compute_matrix()
    concurrency_raw, concurrency_summary = concurrency_matrix()
    summary = {
        "run_id": args.run_id,
        "evidence_class": "valid_signature_microbenchmark_and_modeled_expiry_policy",
        "security_rates": "FAR and ASR not measured; no adversarial proofs submitted",
        "timing_endpoint": "local canonicalization, signing, and verification; no human or network delay",
        "expiry": {
            "cells": len(expiry),
            "policy_rejections": sum(row["policy_rejection"] for row in expiry),
            "false_rejections": sum(row["false_rejection"] for row in expiry),
            "exact_boundary_acceptances": sum(row["accepted"] for row in expiry if row["boundary_relation"] == "at"),
        },
        "compute": compute_summary,
        "concurrency": concurrency_summary,
    }
    write_csv(paths["expiry"], expiry)
    write_csv(paths["compute_raw"], compute_raw)
    write_csv(paths["concurrency_raw"], concurrency_raw)
    write_json(paths["summary"], summary)
    write_table(paths["table"], compute_summary, concurrency_summary)
    manifest = {
        "run_id": args.run_id,
        "repository_commit": git("rev-parse", "HEAD"),
        "repository_dirty": dirty,
        "python_version": platform.python_version(),
        "cryptography_version": cryptography.__version__,
        "platform": platform.platform(),
        "algorithm": "ECDSA P-256 with SHA-256",
        "runner_sha256": sha256_file(Path(__file__)),
        "canonicalizer_sha256": sha256_file(ROOT / "app" / "intent_codec.py"),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "sensitivity_analysis_preregistration.md"),
        "configuration": {
            "ttls_s": TTLS,
            "modeled_delays_s": DELAYS,
            "parameter_counts": PARAMETER_COUNTS,
            "complexities": COMPLEXITIES,
            "compute_samples_per_cell": COMPUTE_SAMPLES,
            "concurrencies": CONCURRENCIES,
            "concurrency_operations_per_cell": CONCURRENCY_OPERATIONS,
        },
    }
    write_json(paths["manifest"], manifest)
    artifacts = (Path(__file__), paths["manifest"], paths["expiry"], paths["compute_raw"], paths["concurrency_raw"], paths["summary"], paths["table"])
    paths["checksums"].write_text("\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in artifacts) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
