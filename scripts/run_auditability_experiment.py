#!/usr/bin/env python3
"""Auditability reconstruction experiment for PoIA."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List


REQUIRED_FIELDS = ("who", "action", "scope", "when", "context", "proof", "outcome_reason")


def h(data: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def build_event(index: int, outcome: str) -> Dict[str, Any]:
    intent = {
        "action": "transfer",
        "scope": {"from_account": f"CHK-{index:04d}", "to_account": f"EXT-{index:04d}", "amount": 100 + index, "currency": "USD"},
        "context": {"rp_id": "poia-bank", "user_id": f"user-{index % 5}", "session_id": f"s-{index % 3}"},
        "constraints": {"nonce": f"nonce-{index}", "expires_at": 1_900_000_000 + index},
    }
    return {"id": f"evt-{index}", "intent": intent, "outcome": outcome}


def baseline_log(event: Dict[str, Any], ts: int) -> Dict[str, Any]:
    intent = event["intent"]
    return {
        "log_type": "baseline",
        "event_id": event["id"],
        "timestamp": ts,
        "session_id": intent["context"]["session_id"],
        "user_id": intent["context"]["user_id"],
        "route": f"/{intent['action']}",
        "status": "executed" if event["outcome"] == "executed" else "rejected",
        "message": "session authorized request",
    }


def poia_log(event: Dict[str, Any], ts: int) -> Dict[str, Any]:
    intent = event["intent"]
    return {
        "log_type": "poia",
        "event_id": event["id"],
        "timestamp": ts,
        "who": intent["context"]["user_id"],
        "action": intent["action"],
        "scope": intent["scope"],
        "context": intent["context"],
        "proof": {"intent_hash": h(intent), "nonce": intent["constraints"]["nonce"], "key_ref": "device-key-1"},
        "status": event["outcome"],
        "outcome_reason": "verified_intent_executed" if event["outcome"] == "executed" else "semantic_mismatch",
    }


def reconstruct(row: Dict[str, Any]) -> tuple[Dict[str, Any], float]:
    start = time.perf_counter()
    if row["log_type"] == "poia":
        reconstructed = {
            "who": row.get("who"),
            "action": row.get("action"),
            "scope": row.get("scope"),
            "when": row.get("timestamp"),
            "context": row.get("context"),
            "proof": row.get("proof"),
            "outcome_reason": row.get("outcome_reason"),
        }
    else:
        reconstructed = {
            "who": row.get("user_id"),
            "action": row.get("route", "").lstrip("/") or None,
            "scope": None,
            "when": row.get("timestamp"),
            "context": {"session_id": row.get("session_id")} if row.get("session_id") else None,
            "proof": None,
            "outcome_reason": row.get("message"),
        }
    elapsed = (time.perf_counter() - start) * 1000
    return reconstructed, elapsed


def score(reconstructed: Dict[str, Any]) -> Dict[str, Any]:
    present = {field: bool(reconstructed.get(field)) for field in REQUIRED_FIELDS}
    missing = [field for field, ok in present.items() if not ok]
    ambiguous = []
    if reconstructed.get("scope") is None:
        ambiguous.append("scope")
    if reconstructed.get("proof") is None:
        ambiguous.append("proof")
    completeness = sum(1 for ok in present.values() if ok) / len(REQUIRED_FIELDS) * 100.0
    return {
        "reconstruction_completeness": round(completeness, 3),
        "missing_fields": missing,
        "missing_evidence_rate": round(len(missing) / len(REQUIRED_FIELDS) * 100.0, 3),
        "ambiguity_rate": round(len(ambiguous) / len(REQUIRED_FIELDS) * 100.0, 3),
    }


def summarize(values: List[float]) -> Dict[str, float]:
    return {"median": statistics.median(values), "mean": statistics.mean(values), "max": max(values), "n": len(values)} if values else {"median": 0, "mean": 0, "max": 0, "n": 0}


def run(events: int) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    logs: List[Dict[str, Any]] = []
    rows: List[Dict[str, Any]] = []
    ts = 1_800_000_000
    for i in range(1, events + 1):
        outcome = "executed" if i % 4 else "rejected"
        event = build_event(i, outcome)
        logs.append(baseline_log(event, ts + i))
        logs.append(poia_log(event, ts + i))
    for log in logs:
        reconstructed, elapsed = reconstruct(log)
        scored = score(reconstructed)
        rows.append(
            {
                "log_type": log["log_type"],
                "event_id": log["event_id"],
                "reconstruction_completeness": scored["reconstruction_completeness"],
                "ambiguity_rate": scored["ambiguity_rate"],
                "missing_evidence_rate": scored["missing_evidence_rate"],
                "missing_fields": ";".join(scored["missing_fields"]),
                "reconstruction_time_ms": elapsed,
            }
        )
    summary = []
    for log_type in ("baseline", "poia"):
        subset = [row for row in rows if row["log_type"] == log_type]
        summary.append(
            {
                "log_type": log_type,
                "events": len(subset),
                "reconstruction_completeness_mean": statistics.mean(float(row["reconstruction_completeness"]) for row in subset),
                "ambiguity_rate_mean": statistics.mean(float(row["ambiguity_rate"]) for row in subset),
                "missing_evidence_rate_mean": statistics.mean(float(row["missing_evidence_rate"]) for row in subset),
                "reconstruction_time_ms": summarize([float(row["reconstruction_time_ms"]) for row in subset]),
            }
        )
    return logs, rows, summary


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


def write_md(path: Path, summary: List[Dict[str, Any]]) -> None:
    lines = [
        "# PoIA Auditability Reconstruction",
        "",
        "| Log Type | Events | Reconstruction Completeness | Ambiguity Rate | Missing Evidence Rate | Median Reconstruction Time (ms) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in summary:
        lines.append(
            f"| {item['log_type']} | {item['events']} | {item['reconstruction_completeness_mean']:.1f}% | "
            f"{item['ambiguity_rate_mean']:.1f}% | {item['missing_evidence_rate_mean']:.1f}% | {item['reconstruction_time_ms']['median']:.6f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run auditability reconstruction experiment.")
    parser.add_argument("--events", type=int, default=120)
    parser.add_argument("--out-dir", default="experiments/auditability")
    args = parser.parse_args()
    logs, rows, summary = run(args.events)
    out = Path(args.out_dir)
    write_json(out / "auditability_logs.json", logs)
    write_json(out / "auditability_summary.json", {"experiment": "auditability", "events_per_mode": args.events, "summary": summary})
    write_csv(out / "auditability_reconstruction.csv", rows)
    write_md(out / "auditability_table.md", summary)
    print(json.dumps({"experiment": "auditability", "events_per_mode": args.events, "summary": summary}, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
