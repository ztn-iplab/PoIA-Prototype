#!/usr/bin/env python3
"""Functional correctness of the REAL PoIA canonicalization and state machine.

WHAT CHANGED AND WHY
--------------------
An earlier version of this script reimplemented the verifier locally (its own
canonical_json, its own HMAC proof check, and an if-ladder standing in for the
gate). It therefore validated its own copy: it would have reported perfect
correctness even if app/core.py were broken. This version calls the production
pipeline directly --
    app.core.create_poia_intent -> poia_store.approve_proof
                                -> poia_store.reserve_execution
    app.intent_codec.canonical_json  (the real canonicalizer)
-- so a regression in the prototype shows up here as a failure.

DESIGN
------
* Randomized inputs. Every trial draws a fresh operation from a seeded RNG, so
  N trials are N distinct inputs rather than N repeats of one fixture.
* Independent oracle. Expected decisions are derived from `indep_canonical`, a
  normalizer written here from unicodedata + json ONLY. It never imports the
  application's canonicalizer, so agreement between the two is evidence rather
  than tautology; disagreements are counted and reported.
* Non-vacuous equivalence tests. A canonical-equivalence case is only
  meaningful if the two encodings really are byte-different before
  normalization. Each such trial asserts that and records it.
* Fails loudly. Any incorrect decision, or any oracle disagreement, exits
  non-zero. See scripts/_functional_correctness_mutation_wrapper.py for the
  control demonstrating this script detects a broken verifier.

SCOPE
-----
Covers canonicalization equality and the execution state machine. It does NOT
cover signature unforgeability: approvals are installed through a fixture
ProofRecord, so cryptographic binding is out of scope here and is established
by the Tamarin model and by WebAuthn/ZT-Authenticator verification in
deployment.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ACCENTED_NAMES = ["José Álvarez", "Renée Dubé", "Søren Kierkegård", "Zoë Müller", "François Béart"]
CURRENCIES = ["USD", "EUR", "GBP", "CHF"]

# Manuscript row -> ordered list of category keys feeding it.
TABLE_ROWS = [
    ("Exact valid match", ["exact_valid_match"], "Accept"),
    ("Canonical equivalent", ["canonical_equivalent_unicode", "canonical_equivalent_numeric"], "Accept"),
    ("Action mismatch", ["action_mismatch"], "Reject"),
    ("Scope mismatch", ["scope_mismatch"], "Reject"),
    ("Context mismatch", ["context_mismatch"], "Reject"),
    ("Expired intent", ["expired_intent"], "Reject"),
    ("Nonce reuse", ["nonce_reuse"], "Reject"),
    ("Malformed serialization", ["malformed_serialization"], "Reject"),
]
CATEGORIES = [c for _row, cats, _e in TABLE_ROWS for c in cats]
ACCEPT_CATEGORIES = {c for _r, cats, exp in TABLE_ROWS if exp == "Accept" for c in cats}


def indep_normalize(value: Any) -> Any:
    """Independent normalizer: unicodedata + plain Python only.

    Deliberately does NOT import app.intent_codec. Mirrors the documented
    normalization contract (NFC strings and keys, integral floats to int,
    sorted keys) so the application's canonicalizer can be cross-checked
    against a separately written implementation.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    if isinstance(value, list):
        return [indep_normalize(v) for v in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", k): indep_normalize(v) for k, v in value.items()}
    raise TypeError(f"unsupported: {type(value).__name__}")


def indep_canonical(value: Any) -> str:
    return json.dumps(indep_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def to_nfd(value: str) -> str:
    return unicodedata.normalize("NFD", value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Functional correctness against the real PoIA pipeline.")
    parser.add_argument("--trials", type=int, default=60, help="Trials per category")
    parser.add_argument("--seed", type=int, default=20260910)
    parser.add_argument("--out-dir", default="experiments/functional_correctness_stress")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from app import db

    db.DB_PATH = out_dir / "functional_correctness.db"
    if db.DB_PATH.exists():
        db.DB_PATH.unlink()
    from app.core import create_poia_intent, poia_store
    from app.intent_codec import canonical_json as app_canonical_json
    from app.model import ProofRecord

    db.init_db()
    with db.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            ("functional-correctness@example.invalid", "unused", int(time.time())),
        ).lastrowid

    rng = random.Random(args.seed)

    def draw_operation() -> Dict[str, Any]:
        return {
            "action": "transfer",
            "scope": {
                "from_account": rng.randint(1, 9999),
                "amount": rng.randint(1, 500000),
                "currency": rng.choice(CURRENCIES),
                "external_account": f"{rng.randint(0, 99999999):08d}",
                "beneficiary_name": rng.choice(ACCENTED_NAMES),
            },
            "context": {"rp_id": f"rp-{rng.randint(0, 9999):04d}", "user_id": user_id},
        }

    def new_approved_intent(op: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        intent_id = create_poia_intent(
            action=op["action"], scope=dict(op["scope"]), context=dict(op["context"])
        )
        ok, why = poia_store.approve_proof(
            ProofRecord(intent_id, "fixture", "approved", "Approved", 0), time.time()
        )
        if not ok:
            raise RuntimeError(f"fixture approval failed: {why}")
        return intent_id, json.loads(json.dumps(poia_store.intents[intent_id].intent_body))

    def mutated(body: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
        out = json.loads(json.dumps(body))
        node = out
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        return out

    rows: List[Dict[str, Any]] = []

    for category in CATEGORIES:
        for attempt in range(1, args.trials + 1):
            op = draw_operation()
            intent_id, approved = new_approved_intent(op)
            requested: Any = approved
            principal = user_id
            expired = False
            preconsumed = False
            serialization_differs = ""
            malformed_kind = ""

            if category == "exact_valid_match":
                pass
            elif category == "canonical_equivalent_unicode":
                name = approved["scope"]["beneficiary_name"]
                requested = mutated(approved, "scope.beneficiary_name", to_nfd(name))
                # Non-vacuity: the two encodings must really differ as bytes.
                serialization_differs = json.dumps(requested, sort_keys=True) != json.dumps(
                    approved, sort_keys=True
                )
                if not serialization_differs:
                    raise RuntimeError("unicode equivalence trial is vacuous: NFD == NFC")
            elif category == "canonical_equivalent_numeric":
                amount = approved["scope"]["amount"]
                requested = mutated(approved, "scope.amount", float(amount))
                serialization_differs = json.dumps(requested, sort_keys=True) != json.dumps(
                    approved, sort_keys=True
                )
                if not serialization_differs:
                    raise RuntimeError("numeric equivalence trial is vacuous")
            elif category == "action_mismatch":
                requested = mutated(approved, "action", "withdrawal")
            elif category == "scope_mismatch":
                new_amount = approved["scope"]["amount"]
                while new_amount == approved["scope"]["amount"]:
                    new_amount = rng.randint(1, 500000)
                requested = mutated(approved, "scope.amount", new_amount)
            elif category == "context_mismatch":
                requested = mutated(
                    approved, "context.rp_id", f"rp-adversary-{rng.randint(0, 10 ** 9):09d}"
                )
            elif category == "expired_intent":
                # Approved while fresh, executed after the validity window closed.
                poia_store.challenges[intent_id].expires_at = time.time() - 1.0
                expired = True
            elif category == "nonce_reuse":
                poia_store.reserve_execution(intent_id, principal, time.time(), approved)
                preconsumed = True
            elif category == "malformed_serialization":
                malformed_kind = rng.choice(
                    ["non_finite_float", "unsupported_type", "non_string_key", "nfc_key_collision"]
                )
                if malformed_kind == "non_finite_float":
                    requested = mutated(approved, "scope.amount", float("nan"))
                elif malformed_kind == "unsupported_type":
                    requested = mutated(approved, "scope.amount", b"not-a-number")
                elif malformed_kind == "non_string_key":
                    requested = json.loads(json.dumps(approved))
                    requested["scope"][7] = "integer-key"
                else:
                    requested = json.loads(json.dumps(approved))
                    requested["scope"]["café_note"] = "nfd form"
                    requested["scope"]["café_note"] = "nfc form"

            # ---- independent expectation, derived before calling the app ----
            if category == "malformed_serialization":
                indep_expected = "reject"
            else:
                try:
                    same = indep_canonical(requested) == indep_canonical(approved)
                except TypeError:
                    same = False
                indep_expected = (
                    "accept"
                    if (same and principal == approved["context"]["user_id"] and not expired and not preconsumed)
                    else "reject"
                )

            # ---- the real pipeline decides ----
            raised = ""
            try:
                accepted, reason, _, _ = poia_store.reserve_execution(
                    intent_id, principal, time.time(), requested
                )
            except Exception as exc:  # malformed input rejected by raising
                accepted, reason = False, f"exception:{type(exc).__name__}"
                raised = f"{type(exc).__name__}: {exc}"

            decision = "accept" if accepted else "reject"
            expected_decision = "accept" if category in ACCEPT_CATEGORIES else "reject"
            rows.append(
                {
                    "category": category,
                    "attempt": attempt,
                    "expected_decision": expected_decision,
                    "independent_expected_decision": indep_expected,
                    "decision": decision,
                    "reason": reason,
                    "raised": raised,
                    "malformed_kind": malformed_kind,
                    "serialization_differs_before_normalization": serialization_differs,
                    "app_canonical_equal": (
                        ""
                        if category == "malformed_serialization"
                        else app_canonical_json(requested) == app_canonical_json(approved)
                    ),
                    "independent_canonical_equal": (
                        "" if category == "malformed_serialization" else indep_canonical(requested) == indep_canonical(approved)
                    ),
                    "correct": decision == expected_decision,
                    "oracle_agrees": indep_expected == decision,
                }
            )

    # ---------------- aggregation ----------------
    per_category: Dict[str, Dict[str, Any]] = {}
    for category in CATEGORIES:
        sel = [r for r in rows if r["category"] == category]
        per_category[category] = {
            "cases": len(sel),
            "expected": "Accept" if category in ACCEPT_CATEGORIES else "Reject",
            "correct": sum(bool(r["correct"]) for r in sel),
            "errors": sum(not bool(r["correct"]) for r in sel),
            "oracle_disagreements": sum(not bool(r["oracle_agrees"]) for r in sel),
            "reasons": sorted({r["reason"] for r in sel if r["decision"] == "reject"}),
        }

    table = []
    for label, cats, expected in TABLE_ROWS:
        sel = [r for r in rows if r["category"] in cats]
        table.append(
            {
                "row": label,
                "cases": len(sel),
                "expected": expected,
                "correct": sum(bool(r["correct"]) for r in sel),
                "errors": sum(not bool(r["correct"]) for r in sel),
            }
        )

    accept_rows = [r for r in rows if r["category"] in ACCEPT_CATEGORIES]
    reject_rows = [r for r in rows if r["category"] not in ACCEPT_CATEGORIES]
    false_rejections = sum(r["decision"] == "reject" for r in accept_rows)
    false_acceptances = sum(r["decision"] == "accept" for r in reject_rows)

    aggregate = {
        "experiment": "functional_correctness_real_pipeline",
        "seed": args.seed,
        "trials_per_category": args.trials,
        "category_count": len(CATEGORIES),
        "total_cases": len(rows),
        "table_rows": table,
        "per_category": per_category,
        "valid_cases": len(accept_rows),
        "invalid_cases": len(reject_rows),
        "false_rejections": false_rejections,
        "false_acceptances": false_acceptances,
        "frr_pct": round(100.0 * false_rejections / len(accept_rows), 4) if accept_rows else None,
        "far_pct": round(100.0 * false_acceptances / len(reject_rows), 4) if reject_rows else None,
        "total_errors": sum(not bool(r["correct"]) for r in rows),
        "total_oracle_disagreements": sum(not bool(r["oracle_agrees"]) for r in rows),
        "verifier": "app.core / app.model poia_store.reserve_execution (production pipeline)",
        "canonicalizer": "app.intent_codec.canonical_json (production), cross-checked against an independently written normalizer",
        "scope_note": "Canonicalization and state machine only; signature unforgeability is out of scope (fixture approvals).",
    }

    write_json = lambda p, d: p.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_json(out_dir / "functional_correctness_summary.json", aggregate)
    write_json(out_dir / "functional_correctness_scenarios.json", {"categories": CATEGORIES, "table_rows": TABLE_ROWS})
    with (out_dir / "functional_correctness_trials.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    md = ["| Test category | Cases | Expected | Correct | Errors |", "|---|---:|---|---:|---:|"]
    md += [f"| {t['row']} | {t['cases']} | {t['expected']} | {t['correct']} | {t['errors']} |" for t in table]
    md += ["", f"FRR: {aggregate['frr_pct']}%  FAR: {aggregate['far_pct']}%"]
    (out_dir / "functional_correctness_table.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return 0 if (aggregate["total_errors"] == 0 and aggregate["total_oracle_disagreements"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
