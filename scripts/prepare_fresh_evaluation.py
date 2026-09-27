#!/usr/bin/env python3
"""Preview or remove superseded empirical outputs; preserve formative and operational state."""

import argparse
import csv
import hashlib
import json
import os
import sqlite3
from pathlib import Path


def generated_files(root):
    experiment = root / "experiments"
    disposable = {"auditability", "cross_domain_generality", "oauth_api_integration",
                  "sensitivity_analysis", "usability_structured", "lifecycle_resilience"}
    for path in sorted(experiment.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix == ".spthy" or "tamarin" in path.name or "lemma_map" in path.name:
            continue
        parts = path.relative_to(experiment).parts
        selected = parts[0] in disposable
        selected |= parts[0] in {"track_a", "track_b", "track_c"} and len(parts) > 2 and parts[1] in {"raw", "analysis", "tables", "manifests"}
        selected |= parts[0] == "manuscript_20260824" and len(parts) > 2 and parts[1] in {"runs", "figures"}
        selected |= parts[0] == "manuscript_20260825"
        selected |= parts[:2] == ("human_pilot", "protocol_enforcement")
        if selected:
            yield path
    for name in ("poia_latency.pdf", "verification_throughput.pdf"):
        path = root / "PoIA_Extended" / name
        if path.is_file():
            yield path


def table_fingerprint(conn):
    tables = ("users", "accounts", "devices", "device_keys", "webauthn_credentials",
              "totp_recovery_codes", "beneficiaries", "transactions", "poia_records",
              "poia_execution_journal", "poia_human_study_trials",
              "poia_human_study_events", "poia_participant_sessions")
    result = {}
    for table in tables:
        rows = conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
        payload = json.dumps(rows, default=str, separators=(",", ":")).encode()
        result[table] = {"rows": len(rows), "sha256": hashlib.sha256(payload).hexdigest()}
    return result


def reset_telemetry(data, apply):
    """Run only with the bank stopped: telemetry CSV writers do not share a DB lock."""
    conn = sqlite3.connect((data / "bank.db").resolve().as_uri() + "?mode=ro", uri=True)
    try:
        before = table_fingerprint(conn)
        human_intents = {row[0] for row in conn.execute("SELECT intent_id FROM poia_human_study_trials")}
        path = data / "poia_experiments.csv"
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            fields = reader.fieldnames
            rows = list(reader)
        retained = [row for row in rows if row.get("intent_id") in human_intents]
        if apply:
            temporary = path.with_suffix(".reset-tmp")
            with temporary.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(retained)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        after = table_fingerprint(conn)
        if before != after:
            raise RuntimeError("Protected records changed; the bank must be stopped during reset")
        return {"removed_timing_rows": len(rows) - len(retained),
                "retained_formative_timing_rows": len(retained),
                "protected_tables": before, "database_modified": False}
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.repo and not args.data_dir:
        parser.error("select --repo and/or --data-dir; default is a non-destructive preview")
    result = {"applied": args.apply}
    if args.repo:
        files = list(generated_files(args.repo.resolve()))
        result["generated_files"] = [str(p.relative_to(args.repo.resolve())) for p in files]
        if args.apply:
            for path in files:
                path.unlink()
    if args.data_dir:
        result["telemetry"] = reset_telemetry(args.data_dir, args.apply)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
