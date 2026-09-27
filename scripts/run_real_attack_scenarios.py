#!/usr/bin/env python3
"""Randomized, positively-controlled attack-outcome experiment (tab:attack-success).

WHAT THIS MEASURES
------------------
The PoIA *binding and state-machine* layer: given that a valid approval for
intent I exists, can an adversary cause a protected execution that does not
correspond to I? Each trial constructs a genuine adversarial input and reads
the real, unmodified return value of the production pipeline
(app.core.create_poia_intent -> poia_store.approve_proof ->
poia_store.reserve_execution, or a second approve_proof for proof reuse).

WHAT THIS DOES NOT MEASURE
--------------------------
The *cryptographic* layer. This harness installs approvals through a fixture
ProofRecord and therefore cannot test whether an adversary can forge or
transplant a signature; that property is established symbolically in the
Tamarin model and, in deployment, by WebAuthn/ZT-Authenticator signature
verification. Nothing here should be read as evidence about signature
unforgeability, nor as a live end-to-end or human-in-the-loop result.

DESIGN
------
* Randomized inputs. Every trial draws fresh account numbers, amounts,
  currencies, workflow and delegation identifiers, relying-party ids, and
  adversarial substitution values from a seeded RNG, so N trials are N
  distinct adversarial inputs rather than N repeats of one input. Each
  mutation is constructed to be value-distinct from the approved field.
* Paired positive control. Every attack trial is paired with an independent,
  freshly created intent executed legitimately and unmodified, which MUST be
  accepted. A gate that rejected all input would fail the control arm, so the
  attack arm's rejection rate is only meaningful alongside it.
* Independent oracle. The expected decision is derived before the call, from
  the experiment's own construction and a digest computed with plain
  json.dumps + hashlib, deliberately NOT the application's canonicalizer.

The baseline arm is definitional, not measured: an application with no
intent-binding layer performs no comparison between an approved intent and a
requested execution, so every construction below succeeds by the absence of a
check. It is reported as such, matching run_attack_baseline.py's own
"baseline_no_intent_binding" labeling.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CURRENCIES = ["USD", "EUR", "GBP", "JPY", "CHF"]


def indep_digest(obj: Any) -> str:
    """Digest computed WITHOUT the application's canonicalizer (independent oracle)."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


SCENARIOS = {
    "replay": (
        "Replay attempt",
        "Re-present an already-consumed approval for the identical operation.",
        "proof_consumed",
    ),
    "relay_semantic_change": (
        "Relay with semantic change",
        "Relay a valid approval to an execution whose scope differs from the approved scope.",
        "scope_mismatch",
    ),
    "session_hijacking": (
        "Session hijacking / misuse",
        "Cross-principal redirect: a different authenticated principal consumes the victim's approval.",
        "principal_mismatch",
    ),
    "request_tampering": (
        "Request tampering",
        "Alter the relying-party binding of the execution request after approval.",
        "rp_mismatch",
    ),
    "proof_reuse": (
        "Token or proof reuse",
        "Re-submit an approval for an intent whose proof is no longer pending.",
        "replay",
    ),
    "confused_deputy": (
        "Confused-deputy workflow",
        "An intermediary applies an approval issued for one workflow to a different workflow.",
        "workflow_mismatch",
    ),
    "multi_step_abuse": (
        "Multi-step operation abuse",
        "Apply an approval issued for one step of a workflow to a different action.",
        "action_mismatch",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repetitions", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260910)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "experiments" / "protocol_vectors" / "attack_outcomes",
    )
    parser.add_argument("--scenarios", nargs="*", default=None)
    args = parser.parse_args()
    if args.repetitions < 1:
        raise SystemExit("repetitions must be positive")

    run_dir = args.out_dir / args.run_id
    raw_dir = run_dir / "raw"
    derived_dir = run_dir / "derived"
    raw_dir.mkdir(parents=True, exist_ok=False)
    derived_dir.mkdir(parents=True, exist_ok=False)

    from app import db

    db.DB_PATH = raw_dir / "attack_vectors.db"
    from app.core import create_poia_intent, poia_store
    from app.model import ProofRecord

    db.init_db()
    with db.db_connect() as conn:
        victim_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            ("attack-fixture-victim@example.invalid", "unused", int(time.time())),
        ).lastrowid
        adversary_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            ("attack-fixture-adversary@example.invalid", "unused", int(time.time())),
        ).lastrowid

    rng = random.Random(args.seed)

    def draw_operation() -> Dict[str, Any]:
        """Draw one randomized legitimate operation for this trial."""
        return {
            "action": "transfer",
            "scope": {
                "from_account": rng.randint(1, 9999),
                "amount": rng.randint(1, 250000),
                "currency": rng.choice(CURRENCIES),
                "external_account": f"{rng.randint(0, 99999999):08d}",
            },
            "context": {
                "rp_id": f"rp-{rng.randint(0, 9999):04d}",
                "user_id": victim_id,
                "workflow_id": f"wf-{rng.randint(0, 10 ** 9):09d}",
                "on_behalf_of": f"deputy-{rng.randint(0, 9999):04d}",
            },
        }

    def distinct_int(current: int, lo: int, hi: int) -> int:
        value = rng.randint(lo, hi)
        while value == current:
            value = rng.randint(lo, hi)
        return value

    def distinct_token(current: str, prefix: str) -> str:
        value = f"{prefix}-{rng.randint(0, 10 ** 9):09d}"
        while value == current:
            value = f"{prefix}-{rng.randint(0, 10 ** 9):09d}"
        return value

    def make_intent(op: Dict[str, Any]) -> str:
        return create_poia_intent(
            action=op["action"], scope=dict(op["scope"]), context=dict(op["context"])
        )

    def approve(intent_id: str, tag: str):
        return poia_store.approve_proof(
            ProofRecord(intent_id, f"fixture-{tag}", "approved", "Approved", 0), time.time()
        )

    def approved_body(intent_id: str) -> Dict[str, Any]:
        return json.loads(json.dumps(poia_store.intents[intent_id].intent_body))

    def mutate(body: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
        out = json.loads(json.dumps(body))
        node = out
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        return out

    scenario_keys = args.scenarios or list(SCENARIOS)
    for key in scenario_keys:
        if key not in SCENARIOS:
            raise SystemExit(f"unknown scenario: {key}")

    rows: List[Dict[str, Any]] = []

    for scenario in scenario_keys:
        _label, _desc, expected_reason = SCENARIOS[scenario]

        for attempt in range(1, args.repetitions + 1):
            op = draw_operation()

            # ---------------- attack arm ----------------
            target_id = make_intent(op)
            ok, why = approve(target_id, "attack")
            if not ok:
                raise RuntimeError(f"fixture approval failed for {scenario}: {why}")
            approved = approved_body(target_id)
            principal = victim_id
            requested = approved
            preceding_execution = False

            if scenario == "replay":
                poia_store.reserve_execution(target_id, victim_id, time.time(), approved)
                preceding_execution = True
            elif scenario == "relay_semantic_change":
                requested = mutate(
                    approved, "scope.amount", distinct_int(approved["scope"]["amount"], 1, 250000)
                )
            elif scenario == "session_hijacking":
                principal = adversary_id
            elif scenario == "request_tampering":
                requested = mutate(
                    approved,
                    "context.rp_id",
                    distinct_token(approved["context"]["rp_id"], "rp-adversary"),
                )
            elif scenario == "confused_deputy":
                requested = mutate(
                    approved,
                    "context.workflow_id",
                    distinct_token(approved["context"]["workflow_id"], "wf-adversary"),
                )
            elif scenario == "multi_step_abuse":
                requested = mutate(approved, "action", "statement_export")

            # Independent expectation, derived before the call, using this
            # harness's own digest rather than the application's canonicalizer.
            body_differs = indep_digest(requested) != indep_digest(approved)
            principal_differs = principal != approved["context"]["user_id"]
            if scenario == "proof_reuse":
                indep_expected = "reject"  # proof is already out of the pending state
            else:
                indep_expected = (
                    "reject"
                    if (body_differs or principal_differs or preceding_execution)
                    else "accept"
                )

            if scenario == "proof_reuse":
                accepted, reason = approve(target_id, "reuse")
            else:
                accepted, reason, _, _ = poia_store.reserve_execution(
                    target_id, principal, time.time(), requested
                )

            rows.append(
                {
                    "scenario": scenario,
                    "attempt": attempt,
                    "arm": "attack",
                    "independent_expected_decision": indep_expected,
                    "decision": "accept" if accepted else "reject",
                    "reason": reason,
                    "expected_reason": expected_reason,
                    "approved_indep_sha256": indep_digest(approved),
                    "requested_indep_sha256": indep_digest(requested),
                    "body_differs": body_differs,
                    "principal_differs": principal_differs,
                    "correct": (not accepted)
                    and reason == expected_reason
                    and indep_expected == "reject",
                }
            )

            # ---------------- paired positive control ----------------
            # Independent intent, same randomized operation, executed exactly
            # as approved by the legitimate principal. MUST be accepted.
            control_id = make_intent(op)
            ok, why = approve(control_id, "control")
            if not ok:
                raise RuntimeError(f"control approval failed for {scenario}: {why}")
            control_body = approved_body(control_id)
            c_accepted, c_reason, _, _ = poia_store.reserve_execution(
                control_id, victim_id, time.time(), control_body
            )
            rows.append(
                {
                    "scenario": scenario,
                    "attempt": attempt,
                    "arm": "legitimate_control",
                    "independent_expected_decision": "accept",
                    "decision": "accept" if c_accepted else "reject",
                    "reason": c_reason,
                    "expected_reason": "",
                    "approved_indep_sha256": indep_digest(control_body),
                    "requested_indep_sha256": indep_digest(control_body),
                    "body_differs": False,
                    "principal_differs": False,
                    "correct": bool(c_accepted),
                }
            )

    csv_path = raw_dir / "attack_decisions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    per_scenario: Dict[str, Dict[str, Any]] = {}
    for scenario in scenario_keys:
        atk = [r for r in rows if r["scenario"] == scenario and r["arm"] == "attack"]
        ctl = [r for r in rows if r["scenario"] == scenario and r["arm"] == "legitimate_control"]
        atk_success = sum(r["decision"] == "accept" for r in atk)
        ctl_accept = sum(r["decision"] == "accept" for r in ctl)
        label, desc, expected_reason = SCENARIOS[scenario]
        per_scenario[scenario] = {
            "label": label,
            "models": desc,
            "attempts": len(atk),
            "baseline_successes_definitional": len(atk),
            "baseline_asr_pct_definitional": 100.0,
            "poia_successes": atk_success,
            "poia_asr_pct": round(100.0 * atk_success / len(atk), 3) if atk else None,
            "expected_rejection_reason": expected_reason,
            "rejections_matching_expected_reason": sum(
                r["reason"] == expected_reason for r in atk if r["decision"] == "reject"
            ),
            "control_attempts": len(ctl),
            "control_accepted": ctl_accept,
            "control_acceptance_pct": round(100.0 * ctl_accept / len(ctl), 3) if ctl else None,
            "distinct_randomized_inputs": len({r["approved_indep_sha256"] for r in atk}),
            "independent_oracle_disagreements": sum(
                (r["independent_expected_decision"] != r["decision"]) for r in atk + ctl
            ),
        }

    summary = {
        "run_id": args.run_id,
        "experiment": "randomized_controlled_attack_outcomes",
        "seed": args.seed,
        "repetitions_per_scenario": args.repetitions,
        "scenarios": per_scenario,
        "total_rows": len(rows),
        "total_attack_successes": sum(
            r["decision"] == "accept" for r in rows if r["arm"] == "attack"
        ),
        "total_control_rejections": sum(
            r["decision"] == "reject" for r in rows if r["arm"] == "legitimate_control"
        ),
        "total_independent_oracle_disagreements": sum(
            r["independent_expected_decision"] != r["decision"] for r in rows
        ),
        "measures": "PoIA binding and state-machine layer under randomized adversarial input, with paired positive controls.",
        "does_not_measure": [
            "Signature unforgeability or credential transplantation (fixture approvals bypass signature verification; see Tamarin model and WebAuthn/ZT-Authenticator verification).",
            "Live end-to-end HTTP, network, or human-in-the-loop behavior.",
            "Baseline arm is definitional (no intent-binding layer performs any comparison), not measured.",
        ],
    }
    (derived_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "run_id": args.run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "script": "scripts/run_real_attack_scenarios.py",
        "seed": args.seed,
        "repetitions_per_scenario": args.repetitions,
        "scenario_keys": scenario_keys,
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_path = run_dir / "checksums.sha256"
    targets = [manifest_path, csv_path, derived_dir / "summary.json"]
    checksum_path.write_text(
        "".join(f"{digest_file(p)}  {p.relative_to(run_dir)}\n" for p in targets), encoding="ascii"
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    failed = (
        summary["total_attack_successes"]
        or summary["total_control_rejections"]
        or summary["total_independent_oracle_disagreements"]
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
