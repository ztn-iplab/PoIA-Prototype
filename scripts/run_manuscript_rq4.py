#!/usr/bin/env python3
"""Generate manuscript RQ4 comparative-authorization property artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "experiments" / "manuscript_20260824" / "scenarios" / "rq4_comparative_semantics.json"
OUTPUT_ROOT = ROOT / "experiments" / "manuscript_20260824" / "runs"


def git(args: List[str]) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_profiles() -> List[Dict[str, Any]]:
    document = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return document["profiles"]


def summarize(profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "mechanism_count": len(profiles),
        "evidence_class": "declared_representative_property_profiles",
        "interpretation": "conceptual profiles, not measured implementations or a security ranking",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="rq4-comparative-semantics-20260824")
    args = parser.parse_args()
    profiles = load_profiles()
    run_dir = OUTPUT_ROOT / args.run_id
    raw = run_dir / "raw"
    analysis = run_dir / "analysis"
    tables = run_dir / "tables"
    raw.mkdir(parents=True, exist_ok=False)
    analysis.mkdir()
    tables.mkdir()
    with (raw / "profiles.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(profiles[0]))
        writer.writeheader()
        writer.writerows(profiles)
    (raw / "profiles.json").write_text(json.dumps(profiles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "1.0.0",
        "experiment": "RQ4_comparative_semantics",
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scenario_file": str(SCENARIOS.relative_to(ROOT)),
        "scenario_file_sha256": sha256(SCENARIOS),
        "rp_commit": git(["rev-parse", "HEAD"]),
        "rp_tree": git(["rev-parse", "HEAD^{tree}"]),
        "rp_dirty": bool(git(["status", "--porcelain"])),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "evidence_class": "declared_representative_property_profiles",
    }
    summary = {**manifest, "summary": summarize(profiles), "profiles": profiles}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (analysis / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# RQ4 Comparative Authorization Semantics", "", "Structured conceptual profiles; no comparative experiment is implied.", "", "| Mechanism | Semantic substitution | Replay / reuse | Classification |", "|---|---|---|---|"]
    for profile in profiles:
        lines.append(f"| {profile['mechanism']} | {profile['semantic_substitution']} | {profile['replay_reuse']} | {profile['classification']} |")
    (tables / "rq4_comparative_semantics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    paths = [run_dir / "manifest.json", raw / "profiles.csv", raw / "profiles.json", analysis / "summary.json", tables / "rq4_comparative_semantics.md"]
    (analysis / "checksums.sha256").write_text("\n".join(f"{sha256(path)}  {path.relative_to(run_dir)}" for path in sorted(paths)) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": args.run_id, "run_dir": str(run_dir), **summary["summary"]}, indent=2))


if __name__ == "__main__":
    main()
