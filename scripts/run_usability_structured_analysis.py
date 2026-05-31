#!/usr/bin/env python3
"""Structured usability-light analysis for PoIA intent prompts."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, List


SCENARIOS = [
    {
        "name": "bank_transfer",
        "intent": "Transfer 250 USD from CHK-1001 to beneficiary EXT-9007",
        "changed": "Transfer 950 USD from CHK-1001 to beneficiary EXT-9007",
        "changed_field": "amount",
        "required_terms": ["Transfer", "250", "USD", "CHK-1001", "EXT-9007"],
        "prompts_per_session": 2,
    },
    {
        "name": "enterprise_role",
        "intent": "Grant reader role to analyst@example.com in tenant retail for 4 hours",
        "changed": "Grant administrator role to analyst@example.com in tenant retail for 4 hours",
        "changed_field": "role",
        "required_terms": ["Grant", "reader", "analyst@example.com", "retail", "4"],
        "prompts_per_session": 1,
    },
    {
        "name": "healthcare_export",
        "intent": "Export lab_results for patient P-1024 to clinic-b for referral",
        "changed": "Export lab_results for patient P-9999 to clinic-b for referral",
        "changed_field": "patient",
        "required_terms": ["Export", "lab_results", "P-1024", "clinic-b", "referral"],
        "prompts_per_session": 1,
    },
    {
        "name": "cloud_key_rotation",
        "intent": "Rotate key kms-key-77 in project prod-payments region ap-northeast-1",
        "changed": "Rotate key kms-key-root in project prod-payments region ap-northeast-1",
        "changed_field": "object",
        "required_terms": ["Rotate", "kms-key-77", "prod-payments", "ap-northeast-1"],
        "prompts_per_session": 1,
    },
]


def analyze(item: Dict[str, Any]) -> Dict[str, Any]:
    words = item["intent"].split()
    required_present = [term for term in item["required_terms"] if term in item["intent"]]
    changed_detectable = item["intent"] != item["changed"] and item["changed_field"] in {"amount", "role", "patient", "object", "context"}
    complexity_penalty = max(0, len(words) - 14) * 3
    clarity_score = max(0, min(100, len(required_present) / len(item["required_terms"]) * 100 - complexity_penalty))
    estimated_approval_time_s = round(1.2 + 0.18 * len(words), 3)
    confusion_rate = round(max(0, 100 - clarity_score) / 100, 3)
    habituation_risk = "low" if item["prompts_per_session"] <= 2 else "medium" if item["prompts_per_session"] <= 5 else "high"
    return {
        "scenario": item["name"],
        "intent_statement": item["intent"],
        "changed_field": item["changed_field"],
        "word_count": len(words),
        "required_terms_present": len(required_present),
        "required_terms_total": len(item["required_terms"]),
        "understandable_score": round(clarity_score, 3),
        "changed_field_detectable": changed_detectable,
        "estimated_approval_time_s": estimated_approval_time_s,
        "confusion_rate": confusion_rate,
        "habituation_risk": habituation_risk,
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_md(path: Path, rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    lines = [
        "# PoIA Usability-Light Structured Analysis",
        "",
        "| Scenario | Understandable Score | Detects Changed Field | Approval Time (s) | Confusion Rate | Habituation Risk |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['scenario']} | {row['understandable_score']:.1f} | "
            f"{'yes' if row['changed_field_detectable'] else 'no'} | {row['estimated_approval_time_s']:.2f} | "
            f"{row['confusion_rate']:.3f} | {row['habituation_risk']} |"
        )
    lines.extend(
        [
            "",
            f"Mean understandable score: {summary['mean_understandable_score']:.1f}",
            f"Mean estimated approval time: {summary['mean_estimated_approval_time_s']:.2f}s",
            f"Detected changed fields: {summary['detectable_changes']}/{summary['scenario_count']}",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run structured usability-light analysis.")
    parser.add_argument("--out-dir", default="experiments/usability_structured")
    args = parser.parse_args()
    rows = [analyze(item) for item in SCENARIOS]
    summary = {
        "experiment": "usability_structured",
        "scenario_count": len(rows),
        "mean_understandable_score": statistics.mean(row["understandable_score"] for row in rows),
        "mean_estimated_approval_time_s": statistics.mean(row["estimated_approval_time_s"] for row in rows),
        "mean_confusion_rate": statistics.mean(row["confusion_rate"] for row in rows),
        "detectable_changes": sum(1 for row in rows if row["changed_field_detectable"]),
    }
    out = Path(args.out_dir)
    write_json(out / "usability_summary.json", {"summary": summary, "scenarios": rows})
    write_csv(out / "usability_scenarios.csv", rows)
    write_md(out / "usability_table.md", rows, summary)
    print(json.dumps({"summary": summary, "scenarios": rows}, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
