#!/usr/bin/env python3
"""Analyze one manifest-bound Track A run and generate its measured table."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
    ) / denominator
    low = 0.0 if successes == 0 else max(0.0, center - margin)
    high = 1.0 if successes == total else min(1.0, center + margin)
    return low, high


def percentile(values: List[float], proportion: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * proportion
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def metric(successes: int, total: int) -> Dict[str, Any]:
    low, high = wilson_interval(successes, total)
    return {
        "count": successes,
        "total": total,
        "proportion": successes / total if total else 0.0,
        "wilson_95_low": low,
        "wilson_95_high": high,
    }


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            rows.append(row)
    return rows


def analyze(run_dir: Path, allow_incomplete: bool) -> Dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    decisions_path = run_dir / "decisions" / "decisions.jsonl"
    if not manifest_path.exists() or not decisions_path.exists():
        raise ValueError("run directory must contain manifest.json and decisions/decisions.jsonl")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = read_jsonl(decisions_path)
    if not rows:
        raise ValueError("run has no decision records")
    for row in rows:
        if row.get("run_id") != manifest["run_id"]:
            raise ValueError("decision run_id does not match manifest")
    attempts = [int(row["attempt_n"]) for row in rows]
    if len(attempts) != len(set(attempts)):
        raise ValueError("duplicate attempt numbers detected")
    expected_n = int(manifest["sample_size_per_scenario"])
    if not allow_incomplete and len(rows) != expected_n:
        raise ValueError(f"final analysis requires exactly {expected_n} decisions; found {len(rows)}")

    expected_reject = [row for row in rows if row["expected_decision"] == "reject"]
    expected_accept = [row for row in rows if row["expected_decision"] == "accept"]
    attack_successes = sum(bool(row["state_changed"]) for row in expected_reject)
    correct_rejections = sum(
        row["decision"] == "reject" and not row["state_changed"] for row in expected_reject
    )
    incorrect_acceptances = sum(row["decision"] == "accept" for row in expected_reject)
    correct_acceptances = sum(row["decision"] == "accept" for row in expected_accept)
    false_rejections = sum(row["decision"] != "accept" for row in expected_accept)
    latencies = [float(row["latency_ms"]) for row in rows]
    denial_reasons: Dict[str, int] = {}
    for row in rows:
        if row.get("rejection_reason"):
            reason = str(row["rejection_reason"])
            denial_reasons[reason] = denial_reasons.get(reason, 0) + 1
    scenario_ids = sorted({str(row["scenario_id"]) for row in rows})
    return {
        "schema_version": "1.0.0",
        "status": "final" if len(rows) == expected_n else "interim",
        "run_id": manifest["run_id"],
        "configuration": manifest["configuration"],
        "scenario_ids": scenario_ids,
        "observed_n": len(rows),
        "required_n": expected_n,
        "attack_success_rate": metric(attack_successes, len(expected_reject)),
        "correct_rejection_rate": metric(correct_rejections, len(expected_reject)),
        "incorrect_acceptance_rate": metric(incorrect_acceptances, len(expected_reject)),
        "correct_acceptance_rate": metric(correct_acceptances, len(expected_accept)),
        "false_rejection_rate": metric(false_rejections, len(expected_accept)),
        "denial_reasons": dict(sorted(denial_reasons.items())),
        "latency_ms": {
            "n": len(latencies),
            "median": statistics.median(latencies),
            "iqr": percentile(latencies, 0.75) - percentile(latencies, 0.25),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
    }


def percent(metric_value: Dict[str, Any]) -> str:
    return (
        f"{metric_value['count']}/{metric_value['total']} "
        f"({metric_value['proportion'] * 100:.2f}%, "
        f"95% CI {metric_value['wilson_95_low'] * 100:.2f}-{metric_value['wilson_95_high'] * 100:.2f}%)"
    )


def markdown(summary: Dict[str, Any]) -> str:
    lines = [
        f"# Track A Run: {summary['run_id']}",
        "",
        f"Status: **{summary['status']}** ({summary['observed_n']}/{summary['required_n']} observations)",
        "",
        "| Configuration | Scenario | Attack success | Correct rejection | Incorrect acceptance |",
        "|---|---|---:|---:|---:|",
        (
            f"| {summary['configuration']} | {', '.join(summary['scenario_ids'])} | "
            f"{percent(summary['attack_success_rate'])} | "
            f"{percent(summary['correct_rejection_rate'])} | "
            f"{percent(summary['incorrect_acceptance_rate'])} |"
        ),
        "",
        "Latency is reported separately from security outcomes.",
        "",
        "| n | Median (ms) | IQR (ms) | P95 (ms) | P99 (ms) |",
        "|---:|---:|---:|---:|---:|",
        (
            f"| {summary['latency_ms']['n']} | {summary['latency_ms']['median']:.3f} | "
            f"{summary['latency_ms']['iqr']:.3f} | {summary['latency_ms']['p95']:.3f} | "
            f"{summary['latency_ms']['p99']:.3f} |"
        ),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    summary = analyze(run_dir, args.allow_incomplete)
    analysis_dir = run_dir / "analysis"
    table_dir = run_dir / "tables"
    analysis_dir.mkdir(exist_ok=True)
    table_dir.mkdir(exist_ok=True)
    (analysis_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (table_dir / "results.md").write_text(markdown(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
