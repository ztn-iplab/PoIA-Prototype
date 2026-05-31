#!/usr/bin/env python3
"""Expanded local security-effectiveness experiment for PoIA.

The experiment compares a session-only baseline with PoIA for broader
session-abuse scenarios. It is local and deterministic by design: the goal is
to regenerate the paper table and trial evidence without requiring a live
browser, external authenticator, or network service.
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


TEST_SIGNING_KEY = b"poia-security-effectiveness-test-key"


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): normalize(val) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        try:
            if "." not in stripped:
                return int(stripped)
        except ValueError:
            pass
        try:
            return round(float(stripped), 6)
        except ValueError:
            return stripped
    if isinstance(value, float):
        return round(value, 6)
    return value


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
    return canonical_json(
        {
            "intent_hash": intent_hash(intent_body),
            "nonce": nonce,
            "expires_at": int(expires_at),
        }
    )


def sign_proof(intent_body: Dict[str, Any], nonce: str, expires_at: int) -> str:
    return hmac.new(TEST_SIGNING_KEY, proof_message(intent_body, nonce, expires_at), hashlib.sha256).hexdigest()


def verify_signature(intent_body: Dict[str, Any], nonce: str, expires_at: int, signature: str) -> bool:
    return hmac.compare_digest(sign_proof(intent_body, nonce, expires_at), signature)


def base_transfer_intent() -> Dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {
            "from_account": 1,
            "amount": 100.0,
            "currency": "USD",
            "beneficiary_id": 7,
        },
        "context": {
            "rp_id": "poia-demo-bank",
            "user_id": 1,
            "session_id": "session-alpha",
            "tenant": "retail",
            "workflow_id": "wf-transfer-001",
        },
        "constraints": {"expires_in_seconds": 60},
    }


def mutate(intent: Dict[str, Any], path: Tuple[str, ...], value: Any) -> Dict[str, Any]:
    changed = deepcopy(intent)
    cursor: Dict[str, Any] = changed
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return changed


@dataclass(frozen=True)
class AttackScenario:
    name: str
    display_name: str
    requested_intent: Dict[str, Any]
    proof_intent: Dict[str, Any]
    nonce: str
    proof_nonce: str
    expires_delta_s: int
    proof_expires_delta_s: int
    poia_denial_reason: str
    preconsume_nonce: bool = False
    missing_proof: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "requested_intent": self.requested_intent,
            "proof_intent": self.proof_intent,
            "nonce": self.nonce,
            "proof_nonce": self.proof_nonce,
            "expires_delta_s": self.expires_delta_s,
            "proof_expires_delta_s": self.proof_expires_delta_s,
            "poia_denial_reason": self.poia_denial_reason,
            "preconsume_nonce": self.preconsume_nonce,
            "missing_proof": self.missing_proof,
            "notes": self.notes,
        }


def build_scenarios() -> List[AttackScenario]:
    intent = base_transfer_intent()
    nonce = "nonce-security-001"
    beneficiary_intent = {
        "action": "beneficiary_add",
        "scope": {"name": "Mallory", "bank": "Example Bank", "account_number": "999000111"},
        "context": deepcopy(intent["context"]),
        "constraints": {"expires_in_seconds": 60},
    }
    admin_intent = {
        "action": "grant_role",
        "scope": {"target_user": "analyst@example.com", "role": "reader", "tenant": "retail"},
        "context": {"rp_id": "poia-demo-bank", "user_id": 1, "session_id": "session-alpha", "tenant": "retail"},
        "constraints": {"expires_in_seconds": 60},
    }

    return [
        AttackScenario(
            "replay_attack",
            "Replay attack",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "nonce_reuse",
            preconsume_nonce=True,
            notes="Previously accepted proof is submitted again.",
        ),
        AttackScenario(
            "relay_phishing",
            "Relay phishing",
            mutate(intent, ("scope", "beneficiary_id"), 99),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "semantic_mismatch",
            notes="User approves one recipient while relayed request executes another.",
        ),
        AttackScenario(
            "session_misuse",
            "Session misuse",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "missing_proof",
            missing_proof=True,
            notes="Attacker has a valid session but no user-mediated proof.",
        ),
        AttackScenario(
            "intent_substitution",
            "Intent substitution",
            mutate(intent, ("action",), "withdrawal"),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "semantic_mismatch",
            notes="Proof over one action is reused for a different action.",
        ),
        AttackScenario(
            "scope_tampering",
            "Scope tampering",
            mutate(intent, ("scope", "amount"), 900.0),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "semantic_mismatch",
            notes="Amount/value changes after approval.",
        ),
        AttackScenario(
            "context_substitution",
            "Context substitution",
            mutate(intent, ("context", "rp_id"), "evil.example"),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "context_mismatch",
            notes="Proof is presented under the wrong relying-party context.",
        ),
        AttackScenario(
            "expired_proof_reuse",
            "Expired proof reuse",
            deepcopy(intent),
            deepcopy(intent),
            nonce,
            nonce,
            -1,
            -1,
            "expired",
            notes="A stale proof is submitted after its validity window.",
        ),
        AttackScenario(
            "concurrent_session_misuse",
            "Concurrent-session misuse",
            mutate(intent, ("context", "session_id"), "session-beta"),
            deepcopy(intent),
            nonce,
            nonce,
            60,
            60,
            "context_mismatch",
            notes="Proof from one authenticated session is reused in another session.",
        ),
        AttackScenario(
            "multi_step_workflow_abuse",
            "Multi-step workflow abuse",
            deepcopy(intent),
            beneficiary_intent,
            nonce,
            nonce,
            60,
            60,
            "semantic_mismatch",
            notes="Legitimate beneficiary workflow evidence is reused for transfer execution.",
        ),
        AttackScenario(
            "confused_deputy_api_call",
            "Confused-deputy API call",
            mutate(admin_intent, ("scope", "role"), "administrator"),
            deepcopy(admin_intent),
            nonce,
            nonce,
            60,
            60,
            "semantic_mismatch",
            notes="Downstream API receives a broader action than the user-approved delegated call.",
        ),
    ]


def poia_authorize(scenario: AttackScenario, now: int, consumed: set[str]) -> Tuple[bool, str]:
    expires_at = now + scenario.expires_delta_s
    proof_expires_at = now + scenario.proof_expires_delta_s

    if scenario.preconsume_nonce:
        consumed.add(scenario.nonce)
    if now > expires_at:
        return False, "expired"
    if scenario.missing_proof:
        return False, "missing_proof"
    if scenario.proof_nonce != scenario.nonce:
        return False, "nonce_mismatch"
    if scenario.nonce in consumed:
        return False, "nonce_reuse"
    if scenario.requested_intent.get("context", {}).get("rp_id") != scenario.proof_intent.get("context", {}).get("rp_id"):
        return False, "context_mismatch"
    if scenario.requested_intent.get("context", {}).get("session_id") != scenario.proof_intent.get("context", {}).get("session_id"):
        return False, "context_mismatch"

    signature = sign_proof(scenario.proof_intent, scenario.proof_nonce, proof_expires_at)
    if not verify_signature(scenario.requested_intent, scenario.nonce, expires_at, signature):
        return False, "semantic_mismatch"

    consumed.add(scenario.nonce)
    return True, "approved"


def baseline_authorize(_scenario: AttackScenario) -> Tuple[bool, str]:
    return True, "session_only_authorized"


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100.0) if denominator else 0.0, 3)


def run_trials(trials: int) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Dict[str, Any]]], List[Dict[str, Any]]]:
    scenarios = build_scenarios()
    rows: List[Dict[str, Any]] = []
    summary: Dict[str, Dict[str, Dict[str, Any]]] = {"baseline": {}, "poia": {}}
    now = int(time.time())

    for scenario in scenarios:
        for mode in ("baseline", "poia"):
            summary[mode][scenario.name] = {
                "display_name": scenario.display_name,
                "trials": 0,
                "attack_successes": 0,
                "correct_rejections": 0,
                "incorrect_acceptances": 0,
                "unexpected_denials": 0,
                "denial_reasons": {},
            }

        for trial in range(1, trials + 1):
            for mode in ("baseline", "poia"):
                if mode == "baseline":
                    accepted, reason = baseline_authorize(scenario)
                else:
                    accepted, reason = poia_authorize(scenario, now, consumed=set())

                attack_success = accepted
                correct_rejection = not accepted and reason == scenario.poia_denial_reason
                incorrect_acceptance = accepted
                unexpected_denial = not accepted and reason != scenario.poia_denial_reason

                item = summary[mode][scenario.name]
                item["trials"] += 1
                if attack_success:
                    item["attack_successes"] += 1
                if correct_rejection:
                    item["correct_rejections"] += 1
                if incorrect_acceptance:
                    item["incorrect_acceptances"] += 1
                if unexpected_denial:
                    item["unexpected_denials"] += 1
                if not accepted:
                    item["denial_reasons"][reason] = item["denial_reasons"].get(reason, 0) + 1

                rows.append(
                    {
                        "trial": trial,
                        "mode": mode,
                        "scenario": scenario.name,
                        "display_name": scenario.display_name,
                        "expected_poia_denial_reason": scenario.poia_denial_reason,
                        "accepted": accepted,
                        "attack_success": attack_success,
                        "correct_rejection": correct_rejection,
                        "incorrect_acceptance": incorrect_acceptance,
                        "reason": reason,
                    }
                )

    for mode_results in summary.values():
        for item in mode_results.values():
            trials_count = int(item["trials"])
            item["attack_success_rate"] = pct(int(item["attack_successes"]), trials_count)
            item["correct_rejection_rate"] = pct(int(item["correct_rejections"]), trials_count)
            item["incorrect_acceptance_rate"] = pct(int(item["incorrect_acceptances"]), trials_count)

    return rows, summary, [scenario.to_dict() for scenario in scenarios]


def write_json(path: Path, data: Any, *, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=sort_keys) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, summary: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
    lines = [
        "# PoIA Security Effectiveness Expansion",
        "",
        "| Scenario | Baseline Attack Success | PoIA Attack Success | PoIA Correct Rejection | PoIA Incorrect Acceptance | PoIA Denial Reason |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for scenario, baseline in summary["baseline"].items():
        poia = summary["poia"][scenario]
        denial_reasons = ", ".join(f"{reason} ({count})" for reason, count in sorted(poia["denial_reasons"].items()))
        lines.append(
            f"| {baseline['display_name']} | "
            f"{baseline['attack_success_rate']:.1f}% | "
            f"{poia['attack_success_rate']:.1f}% | "
            f"{poia['correct_rejection_rate']:.1f}% | "
            f"{poia['incorrect_acceptance_rate']:.1f}% | "
            f"{denial_reasons or '-'} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run expanded local PoIA security-effectiveness experiment.")
    parser.add_argument("--trials", type=int, default=60, help="Trials per scenario per mode")
    parser.add_argument(
        "--out-dir",
        default="experiments/security_effectiveness_expanded",
        help="Directory for generated JSON/CSV/Markdown artifacts",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    rows, summary, scenarios = run_trials(args.trials)
    aggregate = {
        "experiment": "security_effectiveness_expanded",
        "trials_per_scenario_per_mode": args.trials,
        "scenario_count": len(scenarios),
        "summary": summary,
    }

    write_json(out_dir / "security_effectiveness_summary.json", aggregate)
    write_json(out_dir / "security_effectiveness_scenarios.json", scenarios, sort_keys=False)
    write_csv(out_dir / "security_effectiveness_trials.csv", rows)
    write_markdown(out_dir / "security_effectiveness_table.md", summary)

    print(json.dumps(aggregate, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out_dir}")


if __name__ == "__main__":
    main()
