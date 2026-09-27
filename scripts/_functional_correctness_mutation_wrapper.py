#!/usr/bin/env python3
"""Mutation controls for scripts/measure_functional_correctness.py.

A correctness experiment reporting FAR=0 and FRR=0 is only informative if it
would report otherwise when the system under test is broken. This wrapper
injects a defective component and re-runs the unmodified experiment, which
must then fail (non-zero exit). It tests the HARNESS and never produces
reported results.

POIA_FC_MUTATION=always_accept    gate accepts everything -> false acceptances
POIA_FC_MUTATION=always_reject    gate rejects everything -> false rejections
POIA_FC_MUTATION=no_normalization comparison canonicalizer stops normalizing
                                  (NFC + numeric); canonical-equivalent inputs
                                  must then be wrongly rejected.
"""
import json
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app.model as model  # noqa: E402
from app.core import poia_store  # noqa: E402

MODE = os.environ.get("POIA_FC_MUTATION", "")

if MODE == "always_accept":
    poia_store.reserve_execution = lambda intent_id, principal_id, now, requested_intent_body=None: (
        True, "approved", poia_store.intents.get(intent_id), poia_store.challenges.get(intent_id)
    )
elif MODE == "always_reject":
    poia_store.reserve_execution = lambda intent_id, principal_id, now, requested_intent_body=None: (
        False, "defective_gate_rejects_all", None, None
    )
elif MODE == "no_normalization":
    # app.model binds canonical_json by name; intent_mismatch_reason uses it.
    model.canonical_json = lambda data: json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
else:
    raise SystemExit("set POIA_FC_MUTATION=always_accept|always_reject|no_normalization")

runpy.run_path(str(ROOT / "scripts" / "measure_functional_correctness.py"), run_name="__main__")
