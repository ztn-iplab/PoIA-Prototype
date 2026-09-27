#!/usr/bin/env python3
"""Mutation-test wrapper: deliberately break the gate, then run the attack harness.

Validity control for scripts/run_real_attack_scenarios.py. An experiment that
reports "0 attack successes" is only informative if it would have reported a
non-zero value had the enforcement actually been broken. This wrapper injects
a deliberately defective gate and re-runs the unmodified harness, which must
then fail (non-zero exit). It is a test of the HARNESS, never a source of
reported results.

POIA_HARNESS_MUTATION=always_accept  -> gate accepts everything; the harness
    must detect attack successes.
POIA_HARNESS_MUTATION=always_reject  -> gate rejects everything; the harness
    must detect rejected legitimate controls.
"""
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core import poia_store  # noqa: E402

MODE = os.environ.get("POIA_HARNESS_MUTATION", "")

if MODE == "always_accept":
    def _accept_everything(intent_id, principal_id, now, requested_intent_body=None):
        return True, "approved", poia_store.intents.get(intent_id), poia_store.challenges.get(intent_id)

    def _approve_everything(proof, now):
        proof.status = "approved"
        proof.approved_at = now
        poia_store.proofs[proof.intent_id] = proof
        return True, "approved"

    poia_store.reserve_execution = _accept_everything
    poia_store.approve_proof = _approve_everything

elif MODE == "always_reject":
    def _reject_everything(intent_id, principal_id, now, requested_intent_body=None):
        return False, "defective_gate_rejects_all", None, None

    poia_store.reserve_execution = _reject_everything

else:
    raise SystemExit("set POIA_HARNESS_MUTATION=always_accept|always_reject")

runpy.run_path(str(ROOT / "scripts" / "run_real_attack_scenarios.py"), run_name="__main__")
