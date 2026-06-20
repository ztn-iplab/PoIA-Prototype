#!/usr/bin/env python3
"""Validate and summarize progress for one manual Track A run."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid decision JSON at line {line_number}: {exc}") from exc
    return rows


def status(run_dir: Path) -> Dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise ValueError("manifest.json is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = load_jsonl(run_dir / "decisions" / "decisions.jsonl")
    attempts = [int(row["attempt_n"]) for row in rows]
    duplicate_attempts = sorted(
        attempt for attempt, count in Counter(attempts).items() if count > 1
    )
    request_ids = [str(row["request_id"]) for row in rows]
    duplicate_requests = sorted(
        request_id for request_id, count in Counter(request_ids).items() if count > 1
    )
    snapshots = list((run_dir / "state_snapshots").glob("*.json"))
    requests = list((run_dir / "requests").glob("*.json"))
    timings = list((run_dir / "timings").glob("*.json"))
    expected_links = {(int(row["attempt_n"]), str(row["request_id"])) for row in rows}

    def artifact_links(paths: List[Path]) -> set:
        links = set()
        for path in paths:
            artifact = json.loads(path.read_text(encoding="utf-8"))
            links.add((int(artifact["attempt_n"]), str(artifact["request_id"])))
        return links

    snapshot_links = artifact_links(snapshots)
    request_links = artifact_links(requests)
    timing_links = artifact_links(timings)
    required = int(manifest["sample_size_per_scenario"])
    return {
        "run_id": manifest["run_id"],
        "configuration": manifest["configuration"],
        "required_attempts": required,
        "recorded_attempts": len(rows),
        "remaining_attempts": max(0, required - len(rows)),
        "complete": len(rows) == required,
        "overrun": len(rows) > required,
        "decisions": dict(sorted(Counter(row["decision"] for row in rows).items())),
        "rejection_reasons": dict(
            sorted(Counter(row["rejection_reason"] for row in rows if row.get("rejection_reason")).items())
        ),
        "scenarios": dict(sorted(Counter(row["scenario_id"] for row in rows).items())),
        "state_changes": sum(bool(row["state_changed"]) for row in rows),
        "snapshot_files": len(snapshots),
        "request_files": len(requests),
        "timing_files": len(timings),
        "evidence_bundles_complete": (
            expected_links == snapshot_links == request_links == timing_links
            and len(expected_links) == len(rows)
        ),
        "duplicate_attempt_numbers": duplicate_attempts,
        "duplicate_request_ids": duplicate_requests,
        "manifest_rp_dirty": bool(manifest["rp_repository"]["dirty"]),
        "manifest_authenticator_dirty": bool(
            manifest.get("authenticator_repository")
            and manifest["authenticator_repository"]["dirty"]
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    report = status(args.run_dir.resolve())
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["overrun"] or report["duplicate_attempt_numbers"] or report["duplicate_request_ids"]:
        raise SystemExit(2)
    if report["recorded_attempts"] and not report["evidence_bundles_complete"]:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
