#!/usr/bin/env python3
"""Local PoIA functional-correctness stress test.

This script is intentionally self-contained so the paper's Intent Integrity
claim can be rerun without a live browser, authenticator, or web server.  It
models the verifier conditions used by the prototype: canonical intent
equality, nonce freshness, proof binding, validity window, and single-use
consumption.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


TEST_SIGNING_KEY = b"poia-functional-correctness-test-key"


def normalize_scalar(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in {"true", "false"}:
            return stripped.lower() == "true"
        try:
            if "." not in stripped:
                return int(stripped)
        except ValueError:
            pass
        try:
            number = float(stripped)
            return round(number, 6)
        except ValueError:
            return stripped
    return value


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): normalize(val) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return normalize_scalar(value)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        normalize(data),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def intent_hash(intent_body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(intent_body)).hexdigest()


def proof_message(intent_body: Dict[str, Any], nonce: str, expires_at: int) -> bytes:
    payload = {
        "intent_hash": intent_hash(intent_body),
        "nonce": nonce,
        "expires_at": int(expires_at),
    }
    return canonical_json(payload)


def sign_proof(intent_body: Dict[str, Any], nonce: str, expires_at: int) -> str:
    return hmac.new(TEST_SIGNING_KEY, proof_message(intent_body, nonce, expires_at), hashlib.sha256).hexdigest()


def verify_signature(intent_body: Dict[str, Any], nonce: str, expires_at: int, signature: str) -> bool:
    expected = sign_proof(intent_body, nonce, expires_at)
    return hmac.compare_digest(expected, signature)


def base_intent() -> Dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {
            "from_account": 1,
            "amount": 100.0,
            "currency": "USD",
            "beneficiary_id": 7,
            "transfer_type": "external",
        },
        "context": {
            "rp_id": "poia-demo-bank",
            "user_id": 1,
            "session_id": "session-alpha",
            "tenant": "retail",
        },
        "constraints": {"expires_in_seconds": 60},
    }


def reordered_intent(intent: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "constraints": deepcopy(intent["constraints"]),
        "context": {
            "tenant": intent["context"]["tenant"],
            "session_id": intent["context"]["session_id"],
            "user_id": intent["context"]["user_id"],
            "rp_id": intent["context"]["rp_id"],
        },
        "scope": {
            "transfer_type": intent["scope"]["transfer_type"],
            "beneficiary_id": intent["scope"]["beneficiary_id"],
            "currency": intent["scope"]["currency"],
            "amount": intent["scope"]["amount"],
            "from_account": intent["scope"]["from_account"],
        },
        "action": intent["action"],
    }


def encoded_equivalent_intent(intent: Dict[str, Any]) -> Dict[str, Any]:
    encoded = deepcopy(intent)
    encoded["scope"]["from_account"] = "1"
    encoded["scope"]["amount"] = "100.00"
    encoded["scope"]["beneficiary_id"] = "7"
    encoded["context"]["user_id"] = "1"
    encoded["constraints"]["expires_in_seconds"] = "60"
    return encoded


def mutate(intent: Dict[str, Any], path: Tuple[str, ...], value: Any) -> Dict[str, Any]:
    changed = deepcopy(intent)
    cursor: Dict[str, Any] = changed
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return changed


@dataclass(frozen=True)
class Scenario:
    name: str
    category: str
    requested_intent: Dict[str, Any]
    proof_intent: Dict[str, Any]
    nonce: str
    proof_nonce: str
    expires_delta_s: int
    proof_expires_delta_s: int
    expect_accept: bool
    expected_reason: str
    preconsume_nonce: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "requested_intent": self.requested_intent,
            "proof_intent": self.proof_intent,
            "nonce": self.nonce,
            "proof_nonce": self.proof_nonce,
            "expires_delta_s": self.expires_delta_s,
            "proof_expires_delta_s": self.proof_expires_delta_s,
            "expect_accept": self.expect_accept,
            "expected_reason": self.expected_reason,
            "preconsume_nonce": self.preconsume_nonce,
        }


def build_scenarios() -> List[Scenario]:
    intent = base_intent()
    nonce = "nonce-functional-001"
    return [
        Scenario(
            "exact_match",
            "correct_acceptance",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            True,
            "approved",
        ),
        Scenario(
            "canonicalization_order_equivalent",
            "canonicalization_order",
            reordered_intent(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            True,
            "approved",
        ),
        Scenario(
            "encoding_variation_equivalent",
            "encoding_variations",
            encoded_equivalent_intent(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            True,
            "approved",
        ),
        Scenario(
            "action_mismatch",
            "action",
            mutate(intent, ("action",), "withdrawal"),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "semantic_mismatch",
        ),
        Scenario(
            "amount_mismatch",
            "amount_value",
            mutate(intent, ("scope", "amount"), 100.01),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "semantic_mismatch",
        ),
        Scenario(
            "target_object_mismatch",
            "target_object",
            mutate(intent, ("scope", "beneficiary_id"), 8),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "semantic_mismatch",
        ),
        Scenario(
            "user_identity_mismatch",
            "user_identity",
            mutate(intent, ("context", "user_id"), 2),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "semantic_mismatch",
        ),
        Scenario(
            "rp_context_mismatch",
            "rp_context",
            mutate(intent, ("context", "rp_id"), "evil.example"),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "semantic_mismatch",
        ),
        Scenario(
            "nonce_mismatch",
            "nonce",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            "nonce-attacker-reuse",
            60,
            60,
            False,
            "nonce_mismatch",
        ),
        Scenario(
            "nonce_reuse",
            "nonce_reuse",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            False,
            "nonce_reuse",
            preconsume_nonce=True,
        ),
        Scenario(
            "proof_timestamp_mismatch",
            "timestamp",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            120,
            False,
            "proof_mismatch",
        ),
        Scenario(
            "expired_validity_window",
            "validity_window",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            -1,
            -1,
            False,
            "expired",
        ),
    ]


def verify_scenario(scenario: Scenario, now: int, consumed: set[str]) -> Tuple[bool, str]:
    expires_at = now + scenario.expires_delta_s
    proof_expires_at = now + scenario.proof_expires_delta_s
    signature = sign_proof(scenario.proof_intent, scenario.proof_nonce, proof_expires_at)
    if scenario.preconsume_nonce:
        consumed.add(scenario.nonce)

    if now > expires_at:
        return False, "expired"
    if scenario.proof_nonce != scenario.nonce:
        return False, "nonce_mismatch"
    if scenario.nonce in consumed:
        return False, "nonce_reuse"
    if not verify_signature(scenario.requested_intent, scenario.nonce, expires_at, signature):
        if intent_hash(scenario.requested_intent) != intent_hash(scenario.proof_intent):
            return False, "semantic_mismatch"
        return False, "proof_mismatch"
    consumed.add(scenario.nonce)
    return True, "approved"


def run_trials(trials: int) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    scenarios = build_scenarios()
    rows: List[Dict[str, Any]] = []
    summary: Dict[str, Dict[str, Any]] = {}
    now = int(time.time())

    for scenario in scenarios:
        category = summary.setdefault(
            scenario.category,
            {
                "test_cases": 0,
                "correct_acceptances": 0,
                "correct_rejections": 0,
                "false_acceptances": 0,
                "false_rejections": 0,
                "unexpected_reasons": 0,
            },
        )
        for trial in range(1, trials + 1):
            consumed: set[str] = set()
            ok, reason = verify_scenario(scenario, now, consumed)
            expected_ok = scenario.expect_accept
            correct = ok == expected_ok and reason == scenario.expected_reason

            category["test_cases"] += 1
            if ok and expected_ok:
                category["correct_acceptances"] += 1
            elif not ok and not expected_ok:
                category["correct_rejections"] += 1
            elif ok and not expected_ok:
                category["false_acceptances"] += 1
            elif not ok and expected_ok:
                category["false_rejections"] += 1
            if reason != scenario.expected_reason:
                category["unexpected_reasons"] += 1

            rows.append(
                {
                    "trial": trial,
                    "scenario": scenario.name,
                    "category": scenario.category,
                    "expected": "accept" if expected_ok else "reject",
                    "actual": "accept" if ok else "reject",
                    "expected_reason": scenario.expected_reason,
                    "actual_reason": reason,
                    "correct": correct,
                }
            )

    return rows, summary, [scenario.to_dict() for scenario in scenarios]


def write_json(path: Path, data: Any, *, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=sort_keys) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, summary: Dict[str, Dict[str, Any]]) -> None:
    lines = [
        "# PoIA Functional Correctness Stress Test",
        "",
        "| Category | Test Cases | Correct Acceptances | Correct Rejections | False Acceptances | False Rejections | Unexpected Reasons |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for category, data in sorted(summary.items()):
        lines.append(
            f"| {category.replace('_', ' ')} | {data['test_cases']} | "
            f"{data['correct_acceptances']} | {data['correct_rejections']} | "
            f"{data['false_acceptances']} | {data['false_rejections']} | "
            f"{data['unexpected_reasons']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local PoIA functional correctness stress tests.")
    parser.add_argument("--trials", type=int, default=60, help="Trials per scenario")
    parser.add_argument(
        "--out-dir",
        default="experiments/functional_correctness_stress",
        help="Directory for reproducible JSON/CSV/Markdown artifacts",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    rows, summary, scenarios = run_trials(args.trials)
    aggregate = {
        "experiment": "functional_correctness_stress",
        "trials_per_scenario": args.trials,
        "scenario_count": len(scenarios),
        "summary": summary,
    }

    write_json(out_dir / "functional_correctness_summary.json", aggregate)
    write_json(out_dir / "functional_correctness_scenarios.json", scenarios, sort_keys=False)
    write_csv(out_dir / "functional_correctness_trials.csv", rows)
    write_markdown(out_dir / "functional_correctness_table.md", summary)

    print(json.dumps(aggregate, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out_dir}")


if __name__ == "__main__":
    main()
