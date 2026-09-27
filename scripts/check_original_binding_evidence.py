#!/usr/bin/env python3
"""Independently check semantic-binding evidence from raw digest relationships."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def oracle(row: dict[str, str]) -> tuple[str, bool]:
    check = row["check"]
    original = row["original_sha256"]
    displayed = row["displayed_sha256"]
    execution = row["execution_sha256"]
    if check == "post_order_pre_approval":
        valid_shape = bool(original and displayed and original != displayed and not execution)
        return "reject", valid_shape
    if check == "post_signature_execution":
        valid_shape = bool(original and original == displayed and execution and displayed != execution)
        return "reject", valid_shape
    if check in {"exact_control", "mutated_exact_control"}:
        valid_shape = bool(original and original == displayed == execution)
        return "accept", valid_shape
    if check == "replay_control":
        valid_shape = bool(
            original
            and original == displayed == execution
            and row["reason"] == "proof_consumed"
        )
        return "reject", valid_shape
    return "unknown", False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    with args.csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    failures: list[dict[str, object]] = []
    grouped: dict[tuple[str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        expected, valid_shape = oracle(row)
        if not valid_shape or row["decision"] != expected:
            failures.append(
                {
                    "mutation_type": row["mutation_type"],
                    "attempt": row["attempt"],
                    "check": row["check"],
                    "valid_digest_relationship": valid_shape,
                    "oracle_decision": expected,
                    "observed_decision": row["decision"],
                }
            )
        grouped[(row["mutation_type"], row["attempt"])][row["check"]] = row

    symmetry_failures = 0
    required = {
        "post_order_pre_approval",
        "mutated_exact_control",
        "post_signature_execution",
        "exact_control",
        "replay_control",
    }
    for checks in grouped.values():
        if set(checks) != required:
            symmetry_failures += 1
            continue
        attack_digest = checks["post_signature_execution"]["execution_sha256"]
        accepted_digest = checks["mutated_exact_control"]["execution_sha256"]
        if not attack_digest or attack_digest != accepted_digest:
            symmetry_failures += 1

    summary = {
        "rows": len(rows),
        "cases": len(grouped),
        "oracle_failures": len(failures),
        "metamorphic_symmetry_failures": symmetry_failures,
        "passed": not failures and symmetry_failures == 0,
        "failure_examples": failures[:10],
    }
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
