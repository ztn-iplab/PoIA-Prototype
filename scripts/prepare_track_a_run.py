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
    parser.add_argument("--browser-or-client-runtime", required=True)
    parser.add_argument("--authenticator-platform", required=True)
    parser.add_argument("--container-runtime", required=True)
    parser.add_argument("--network-rtt-ms", required=True, type=float)
    parser.add_argument("--database-backend", required=True)
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
        experimental_environment={
            "browser_or_client_runtime": args.browser_or_client_runtime,
            "authenticator_platform": args.authenticator_platform,
            "container_runtime": args.container_runtime,
            "network_rtt_ms": args.network_rtt_ms,
            "database_backend": args.database_backend,
            "clock_source": "time.time and time.perf_counter_ns",
        },
    )
    if manifest["rp_repository"]["dirty"]:
        raise SystemExit("refusing reportable run: relying-party repository is dirty")
    authenticator = manifest.get("authenticator_repository")
    if authenticator and authenticator["dirty"]:
        raise SystemExit("refusing reportable run: authenticator repository is dirty")
    run_dir = TRACK_A / "raw" / run_id
    for child in ("decisions", "state_snapshots", "timings", "requests"):
        (run_dir / child).mkdir(parents=True, exist_ok=False)
    manifest_path = run_dir / "manifest.json"
    write_json_atomic(manifest_path, manifest)
    environment = "\n".join(
        [
            f"export POIA_TRACK_A_MANIFEST=/experiments/track_a/raw/{run_id}/manifest.json",
            "export POIA_TRACK_A_SCENARIO_ID=exact_legitimate_match",
            "export POIA_TRACK_A_EXPECTED_DECISION=accept",
            "export POIA_TEST_MODE=false",
            "export POIA_EXPERIMENT_MODE=true",
            "",
        ]
    )
    (run_dir / "run.env").write_text(environment, encoding="utf-8")
    print(f"run_id={run_id}")
    print(f"manifest={manifest_path}")
    print(f"environment={run_dir / 'run.env'}")


if __name__ == "__main__":
    main()
