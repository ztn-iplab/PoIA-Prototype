#!/usr/bin/env python3
"""Validate Track A inputs and create a local run manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from track_a_evidence import TRACK_A, create_manifest, load_scenarios, write_json_atomic


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True, choices=(
        "session_only", "poia_webauthn", "poia_zt_authenticator"
    ))
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--authenticator-repo", type=Path)
    args = parser.parse_args()

    load_scenarios()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = args.run_id or f"{args.configuration}-{args.batch_id}-{stamp}"
    manifest = create_manifest(
        run_id=run_id,
        batch_id=args.batch_id,
        configuration=args.configuration,
        random_seed=args.seed,
        authenticator_repo=args.authenticator_repo,
    )
    run_dir = TRACK_A / "raw" / run_id
    for child in ("decisions", "state_snapshots", "timings", "requests"):
        (run_dir / child).mkdir(parents=True, exist_ok=False)
    manifest_path = run_dir / "manifest.json"
    write_json_atomic(manifest_path, manifest)
    print(f"run_id={run_id}")
    print(f"manifest={manifest_path}")


if __name__ == "__main__":
    main()
