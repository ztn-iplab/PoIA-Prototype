#!/usr/bin/env python3
"""Cross-domain PoIA generality experiment.

The verifier is intentionally domain-agnostic. Each domain changes only the
intent schema. The experiment checks that exact intents are accepted and
domain-specific semantic tampering is rejected.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import statistics
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


KEY = b"poia-cross-domain-verifier-key"


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign(intent: Dict[str, Any]) -> str:
    return hmac.new(KEY, canonical_json(intent), hashlib.sha256).hexdigest()


def verify(proof_intent: Dict[str, Any], requested_intent: Dict[str, Any], signature: str) -> tuple[bool, str, float]:
    start = time.perf_counter()
    expected = sign(proof_intent)
    if not hmac.compare_digest(expected, signature):
        return False, "invalid_signature", (time.perf_counter() - start) * 1000
    if canonical_json(proof_intent) != canonical_json(requested_intent):
        return False, "semantic_mismatch", (time.perf_counter() - start) * 1000
    return True, "approved", (time.perf_counter() - start) * 1000


def mutate(intent: Dict[str, Any], path: Tuple[str, ...], value: Any) -> Dict[str, Any]:
    changed = deepcopy(intent)
    cursor = changed
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return changed


def domain_intents() -> Dict[str, Dict[str, Any]]:
    return {
        "banking_transfer": {
            "action": "transfer",
            "scope": {"from_account": "CHK-1001", "to_account": "EXT-9007", "amount": 250.0, "currency": "USD"},
            "context": {"rp_id": "poia-bank", "user_id": "customer-1", "jurisdiction": "JP"},
            "constraints": {"nonce": "n-bank", "expires_in_seconds": 60},
        },
        "enterprise_admin": {
            "action": "grant_role",
            "scope": {"target_user": "analyst@example.com", "role": "reader", "tenant": "retail", "duration_hours": 4},
            "context": {"rp_id": "poia-iam", "admin_id": "admin-1", "ticket": "CHG-2042"},
            "constraints": {"nonce": "n-iam", "expires_in_seconds": 60},
        },
        "healthcare_export": {
            "action": "export_record",
            "scope": {"patient_id": "P-1024", "record_type": "lab_results", "recipient": "clinic-b", "purpose": "referral"},
            "context": {"rp_id": "poia-health", "clinician_id": "doctor-7", "consent_ref": "CONS-88"},
            "constraints": {"nonce": "n-health", "expires_in_seconds": 60},
        },
        "cloud_api": {
            "action": "rotate_key",
            "scope": {"key_id": "kms-key-77", "project": "prod-payments", "region": "ap-northeast-1"},
            "context": {"rp_id": "poia-cloud", "operator_id": "ops-3", "change_request": "CR-9001"},
            "constraints": {"nonce": "n-cloud", "expires_in_seconds": 60},
        },
    }


def tamper_cases(domain: str, intent: Dict[str, Any]) -> List[tuple[str, Dict[str, Any]]]:
    if domain == "banking_transfer":
        return [
            ("amount_tamper", mutate(intent, ("scope", "amount"), 999.0)),
            ("recipient_tamper", mutate(intent, ("scope", "to_account"), "EXT-ATTACK")),
        ]
    if domain == "enterprise_admin":
        return [
            ("role_escalation", mutate(intent, ("scope", "role"), "administrator")),
            ("tenant_tamper", mutate(intent, ("scope", "tenant"), "executive")),
        ]
    if domain == "healthcare_export":
        return [
            ("patient_tamper", mutate(intent, ("scope", "patient_id"), "P-9999")),
            ("purpose_tamper", mutate(intent, ("scope", "purpose"), "marketing")),
        ]
    return [
        ("key_tamper", mutate(intent, ("scope", "key_id"), "kms-key-root")),
        ("project_tamper", mutate(intent, ("scope", "project"), "prod-identity")),
    ]


def summarize(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"median": 0.0, "mean": 0.0, "max": 0.0, "n": 0}
    return {"median": statistics.median(values), "mean": statistics.mean(values), "max": max(values), "n": len(values)}


def run(trials: int) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    summary: List[Dict[str, Any]] = []
    for domain, intent in domain_intents().items():
        domain_rows: List[Dict[str, Any]] = []
        cases = [("exact_match", intent, True, "approved")]
        cases.extend((name, tampered, False, "semantic_mismatch") for name, tampered in tamper_cases(domain, intent))
        for trial in range(1, trials + 1):
            signature = sign(intent)
            for case_name, requested, expect_accept, expected_reason in cases:
                ok, reason, verify_ms = verify(intent, requested, signature)
                correct = ok == expect_accept and reason == expected_reason
                row = {
                    "domain": domain,
                    "trial": trial,
                    "case": case_name,
                    "expected": "accept" if expect_accept else "reject",
                    "actual": "accept" if ok else "reject",
                    "reason": reason,
                    "correct": correct,
                    "verification_ms": verify_ms,
                }
                rows.append(row)
                domain_rows.append(row)
        total = len(domain_rows)
        accepts = sum(1 for row in domain_rows if row["actual"] == "accept")
        rejects = sum(1 for row in domain_rows if row["actual"] == "reject")
        false_accepts = sum(1 for row in domain_rows if row["expected"] == "reject" and row["actual"] == "accept")
        false_rejects = sum(1 for row in domain_rows if row["expected"] == "accept" and row["actual"] == "reject")
        summary.append(
            {
                "domain": domain,
                "schema_fields": sorted(intent["scope"].keys()),
                "cases": sorted({row["case"] for row in domain_rows}),
                "total_cases": total,
                "correct_acceptances": accepts,
                "correct_rejections": rejects,
                "false_acceptances": false_accepts,
                "false_rejections": false_rejects,
                "verification_ms": summarize([float(row["verification_ms"]) for row in domain_rows]),
            }
        )
    return rows, summary


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
        "# PoIA Cross-Domain Generality",
        "",
        "| Domain | Scope Fields | Cases | Correct Acceptances | Correct Rejections | False Acceptances | False Rejections | Median Verify (ms) |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for item in summary:
        lines.append(
            f"| {item['domain'].replace('_', ' ')} | {', '.join(item['schema_fields'])} | "
            f"{', '.join(item['cases'])} | {item['correct_acceptances']} | {item['correct_rejections']} | "
            f"{item['false_acceptances']} | {item['false_rejections']} | {item['verification_ms']['median']:.4f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PoIA cross-domain generality simulation.")
    parser.add_argument("--trials", type=int, default=60)
    parser.add_argument("--out-dir", default="experiments/cross_domain_generality")
    args = parser.parse_args()
    rows, summary = run(args.trials)
    out = Path(args.out_dir)
    write_json(out / "cross_domain_summary.json", {"experiment": "cross_domain_generality", "trials": args.trials, "summary": summary})
    write_json(out / "cross_domain_schemas.json", domain_intents())
    write_csv(out / "cross_domain_trials.csv", rows)
    write_md(out / "cross_domain_table.md", summary)
    print(json.dumps({"experiment": "cross_domain_generality", "trials": args.trials, "summary": summary}, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
