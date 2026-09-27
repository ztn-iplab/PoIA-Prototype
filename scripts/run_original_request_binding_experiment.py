#!/usr/bin/env python3
"""Confirm original-order, execution-semantic, exact-control, and replay gates."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


MUTATIONS = {
    "action": {"path": "action", "value": "statement_export", "expected": "action_mismatch"},
    "target": {"path": "scope.external_account", "value": "7781", "expected": "scope_mismatch"},
    "scope": {"path": "scope.amount", "value": 1000, "expected": "scope_mismatch"},
    "context": {"path": "context.rp_id", "value": "other-rp", "expected": "rp_mismatch"},
    "subtle_parameter": {"path": "scope.amount", "value": 100.01, "expected": "scope_mismatch"},
}


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="original-binding-confirmatory-01")
    parser.add_argument("--repetitions", type=int, default=200)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "experiments" / "human_pilot" / "protocol_enforcement",
    )
    args = parser.parse_args()
    if args.repetitions < 1:
        raise SystemExit("repetitions must be positive")

    run_dir = args.out_dir / args.run_id
    raw_dir = run_dir / "raw"
    derived_dir = run_dir / "derived"
    raw_dir.mkdir(parents=True, exist_ok=False)
    derived_dir.mkdir(parents=True, exist_ok=False)

    from app import db

    db.DB_PATH = raw_dir / "protocol_evidence.db"
    from app.core import (
        canonical_sha256,
        create_poia_intent,
        original_request_binding_reason,
        poia_store,
    )
    from app.human_study import apply_mutations, canonical_copy
    from app.intent_codec import build_intent
    from app.model import ProofRecord

    db.init_db()
    with db.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            ("protocol-fixture@example.invalid", "unused", int(time.time())),
        ).lastrowid

    poia_store.intents.clear()
    poia_store.challenges.clear()
    poia_store.proofs.clear()
    rows: list[Dict[str, Any]] = []

    mutation_cases = dict(MUTATIONS)
    mutation_cases["multiple_field"] = {
        "mutations": [
            {"path": "scope.amount", "value": 1000},
            {"path": "scope.external_account", "value": "7781"},
        ],
        "expected": "scope_mismatch",
    }

    for mutation_type, definition in mutation_cases.items():
        mutations = definition.get("mutations") or [
            {"path": definition["path"], "value": definition["value"]}
        ]
        for attempt in range(1, args.repetitions + 1):
            original = build_intent(
                action="transfer",
                scope={
                    "from_account": 1,
                    "amount": 100,
                    "currency": "USD",
                    "external_account": "9007",
                },
                context={"rp_id": "poia-demo-bank", "user_id": user_id},
            )
            displayed_mutation = apply_mutations(original, mutations)
            pre_id = create_poia_intent(
                action=str(displayed_mutation["action"]),
                scope=displayed_mutation["scope"],
                context=displayed_mutation["context"],
                original_request_body=original,
            )
            pre_record = poia_store.intents[pre_id]
            pre_reason = original_request_binding_reason(pre_record)
            rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempt": attempt,
                    "check": "post_order_pre_approval",
                    "expected_decision": "reject",
                    "decision": "reject" if pre_reason else "accept",
                    "reason": pre_reason,
                    "original_sha256": pre_record.original_request_hash,
                    "displayed_sha256": canonical_sha256(pre_record.intent_body),
                    "execution_sha256": "",
                    "proof_status": poia_store.proofs[pre_id].status,
                    "correct": pre_reason == "original_request_mismatch",
                }
            )

            # Metamorphic positive control: the exact bytes used as the attack
            # value must be accepted when freshly originated as O = I = E.
            mutated_exact_id = create_poia_intent(
                action=str(displayed_mutation["action"]),
                scope=displayed_mutation["scope"],
                context=displayed_mutation["context"],
                original_request_body=displayed_mutation,
            )
            mutated_approved, mutated_approval_reason = poia_store.approve_proof(
                ProofRecord(
                    mutated_exact_id,
                    "protocol-fixture-mutated-exact",
                    "approved",
                    "Approved",
                    0,
                ),
                time.time(),
            )
            if not mutated_approved:
                raise RuntimeError(
                    f"mutated exact fixture approval failed: {mutated_approval_reason}"
                )
            mutated_accepted, mutated_reason, _, _ = poia_store.reserve_execution(
                mutated_exact_id,
                user_id,
                time.time(),
                displayed_mutation,
            )
            mutated_digest = canonical_sha256(displayed_mutation)
            rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempt": attempt,
                    "check": "mutated_exact_control",
                    "expected_decision": "accept",
                    "decision": "accept" if mutated_accepted else "reject",
                    "reason": mutated_reason,
                    "original_sha256": mutated_digest,
                    "displayed_sha256": mutated_digest,
                    "execution_sha256": mutated_digest,
                    "proof_status": poia_store.proofs[mutated_exact_id].status,
                    "correct": mutated_accepted,
                }
            )

            exact_body = canonical_copy(original)
            post_id = create_poia_intent(
                action=str(exact_body["action"]),
                scope=exact_body["scope"],
                context=exact_body["context"],
                original_request_body=exact_body,
            )
            approved, approval_reason = poia_store.approve_proof(
                ProofRecord(post_id, "protocol-fixture", "approved", "Approved", 0),
                time.time(),
            )
            if not approved:
                raise RuntimeError(f"fixture approval failed: {approval_reason}")
            mutated_execution = apply_mutations(exact_body, mutations)
            accepted, reason, _, _ = poia_store.reserve_execution(
                post_id, user_id, time.time(), mutated_execution
            )
            rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempt": attempt,
                    "check": "post_signature_execution",
                    "expected_decision": "reject",
                    "decision": "accept" if accepted else "reject",
                    "reason": reason,
                    "original_sha256": poia_store.intents[post_id].original_request_hash,
                    "displayed_sha256": canonical_sha256(exact_body),
                    "execution_sha256": canonical_sha256(mutated_execution),
                    "proof_status": poia_store.proofs[post_id].status,
                    "correct": not accepted and reason == definition["expected"],
                }
            )
            exact_accepted, exact_reason, _, _ = poia_store.reserve_execution(
                post_id, user_id, time.time(), exact_body
            )
            rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempt": attempt,
                    "check": "exact_control",
                    "expected_decision": "accept",
                    "decision": "accept" if exact_accepted else "reject",
                    "reason": exact_reason,
                    "original_sha256": poia_store.intents[post_id].original_request_hash,
                    "displayed_sha256": canonical_sha256(exact_body),
                    "execution_sha256": canonical_sha256(exact_body),
                    "proof_status": poia_store.proofs[post_id].status,
                    "correct": exact_accepted,
                }
            )
            replay_accepted, replay_reason, _, _ = poia_store.reserve_execution(
                post_id, user_id, time.time(), exact_body
            )
            rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempt": attempt,
                    "check": "replay_control",
                    "expected_decision": "reject",
                    "decision": "accept" if replay_accepted else "reject",
                    "reason": replay_reason,
                    "original_sha256": poia_store.intents[post_id].original_request_hash,
                    "displayed_sha256": canonical_sha256(exact_body),
                    "execution_sha256": canonical_sha256(exact_body),
                    "proof_status": poia_store.proofs[post_id].status,
                    "correct": not replay_accepted and replay_reason == "proof_consumed",
                }
            )

    csv_path = raw_dir / "decisions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    checks: Dict[str, Dict[str, Any]] = {}
    for check in (
        "post_order_pre_approval",
        "mutated_exact_control",
        "post_signature_execution",
        "exact_control",
        "replay_control",
    ):
        selected = [row for row in rows if row["check"] == check]
        checks[check] = {
            "attempts": len(selected),
            "correct": sum(bool(row["correct"]) for row in selected),
            "incorrect": sum(not bool(row["correct"]) for row in selected),
        }
    summary = {
        "run_id": args.run_id,
        "experiment": "original_request_and_execution_binding",
        "repetitions_per_mutation": args.repetitions,
        "mutation_types": list(mutation_cases),
        "signing_backend": "protocol_fixture_no_human_or_authenticator_claim",
        "checks": checks,
        "total_attempts": len(rows),
        "total_incorrect": sum(not bool(row["correct"]) for row in rows),
        "notes": [
            "This run validates production canonical binding and state-machine logic.",
            "Each attack value is also submitted as a fresh exact operation and must be accepted.",
            "It does not replace live WebAuthn, ZT-Authenticator, or participant trials.",
            "No conference CSV or prior approval dataset was read.",
        ],
    }
    summary_path = derived_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = {
        "run_id": args.run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "script": "scripts/run_original_request_binding_experiment.py",
        "repetitions_per_mutation": args.repetitions,
        "excluded_inputs": ["conference data", "existing CSV approval files"],
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_path = run_dir / "checksums.sha256"
    checksum_targets = [manifest_path, csv_path, summary_path, db.DB_PATH]
    checksum_path.write_text(
        "".join(f"{digest_file(path)}  {path.relative_to(run_dir)}\n" for path in checksum_targets),
        encoding="ascii",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["total_incorrect"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
