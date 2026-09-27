#!/usr/bin/env python3
"""Merge sequential chunked runs of run_original_request_binding_experiment.py.

The sandboxed execution environment used to produce these chunks enforces a
per-call wall-clock budget shorter than a single 200-repetitions/class run of
run_original_request_binding_experiment.py takes to complete. Each chunk is a
fully independent, complete invocation of the unmodified experiment script
(same canonicalization/signing/verification code path, same checks) using a
different --run-id and a smaller --repetitions value. This script only
concatenates their already-computed decisions.csv rows and recomputes the
same summary statistics the original script computes; it does not alter or
re-derive any accept/reject decision.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chunk-dir", action="append", required=True,
                         help="Path to a completed run directory (containing raw/decisions.csv). Repeatable, in order.")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_dir = args.out_dir / args.run_id
    raw_dir = run_dir / "raw"
    derived_dir = run_dir / "derived"
    raw_dir.mkdir(parents=True, exist_ok=False)
    derived_dir.mkdir(parents=True, exist_ok=False)

    per_mutation_next_attempt: Dict[str, int] = {}
    merged_rows: List[Dict[str, Any]] = []
    source_manifest = []
    fieldnames = None

    for chunk_dir_str in args.chunk_dir:
        chunk_dir = Path(chunk_dir_str)
        chunk_csv = chunk_dir / "raw" / "decisions.csv"
        chunk_summary = json.loads((chunk_dir / "derived" / "summary.json").read_text())
        with chunk_csv.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if fieldnames is None:
                fieldnames = reader.fieldnames
            elif reader.fieldnames != fieldnames:
                raise RuntimeError(f"{chunk_csv}: column mismatch with prior chunks")
            # Each logical trial within a source chunk is a contiguous run of
            # rows sharing (mutation_type, original attempt) -- one row per
            # check type. Renumber at the trial level, not the row level, so
            # all rows belonging to one trial keep the same new attempt id.
            seen_in_chunk: Dict[tuple, int] = {}
            for row in reader:
                mtype = row["mutation_type"]
                orig_key = (mtype, row["attempt"])
                if orig_key not in seen_in_chunk:
                    next_attempt = per_mutation_next_attempt.get(mtype, 0) + 1
                    per_mutation_next_attempt[mtype] = next_attempt
                    seen_in_chunk[orig_key] = next_attempt
                row["attempt"] = str(seen_in_chunk[orig_key])
                merged_rows.append(row)
        source_manifest.append({
            "chunk_dir": str(chunk_dir),
            "chunk_run_id": chunk_summary["run_id"],
            "repetitions_per_mutation": chunk_summary["repetitions_per_mutation"],
            "total_attempts": chunk_summary["total_attempts"],
            "total_incorrect": chunk_summary["total_incorrect"],
            "decisions_csv_sha256": digest_file(chunk_csv),
        })

    csv_path = raw_dir / "decisions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(merged_rows)

    checks: Dict[str, Dict[str, Any]] = {}
    for check in (
        "post_order_pre_approval",
        "mutated_exact_control",
        "post_signature_execution",
        "exact_control",
        "replay_control",
    ):
        selected = [row for row in merged_rows if row["check"] == check]
        checks[check] = {
            "attempts": len(selected),
            "correct": sum(row["correct"] in ("True", "true", "1") for row in selected),
            "incorrect": sum(row["correct"] not in ("True", "true", "1") for row in selected),
        }

    total_reps = sum(v for v in per_mutation_next_attempt.values())
    reps_per_mutation = sorted(set(per_mutation_next_attempt.values()))
    summary = {
        "run_id": args.run_id,
        "experiment": "original_request_and_execution_binding",
        "repetitions_per_mutation": reps_per_mutation[0] if len(reps_per_mutation) == 1 else per_mutation_next_attempt,
        "mutation_types": sorted(per_mutation_next_attempt),
        "signing_backend": "protocol_fixture_no_human_or_authenticator_claim",
        "checks": checks,
        "total_attempts": len(merged_rows),
        "total_incorrect": sum(row["correct"] not in ("True", "true", "1") for row in merged_rows),
        "assembled_from_chunks": source_manifest,
        "notes": [
            "This run validates production canonical binding and state-machine logic.",
            "Each attack value is also submitted as a fresh exact operation and must be accepted.",
            "It does not replace live WebAuthn, ZT-Authenticator, or participant trials.",
            "No conference CSV or prior approval dataset was read.",
            "Assembled by concatenating independent complete sub-runs of the unmodified "
            "experiment script (see assembled_from_chunks); no decision logic was re-derived.",
        ],
    }
    summary_path = derived_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "run_id": args.run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "script": "scripts/merge_original_request_binding_chunks.py",
        "source_chunks": source_manifest,
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checksum_path = run_dir / "checksums.sha256"
    checksum_targets = [manifest_path, csv_path, summary_path]
    checksum_path.write_text(
        "".join(f"{digest_file(path)}  {path.relative_to(run_dir)}\n" for path in checksum_targets),
        encoding="ascii",
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["total_incorrect"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
