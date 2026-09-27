import subprocess
import sys
from pathlib import Path

import pytest

from scripts.verify_atomic_referent_binding import audit_extension

ROOT = Path(__file__).resolve().parents[1]


def test_instrumentation_preserves_original_protocol_and_formulas():
    audit_extension((ROOT / "formal-models/atomic_referent_binding.spthy").read_text(),
                    (ROOT / "formal-models/proofs/reference_model.spthy").read_text())


def test_audit_rejects_signature_guard_removal():
    source = (ROOT / "formal-models/proofs/without_signature.spthy").read_text()
    reference = (ROOT / "formal-models/proofs/reference_model.spthy").read_text()
    with pytest.raises(ValueError, match="Changed rule state: Execute"):
        audit_extension(source, reference)


def test_oracle_ranks_all_goals_without_dropping_any():
    result = subprocess.run([sys.executable, str(ROOT / "formal-models/oracle"), "retired_version_not_read"],
        input="0: Current( r, v ) at #m\n1: ReadVersion( r, v ) at #t\n2: Current( r, v ) at #t\n3: input ~~> output\n",
        text=True, capture_output=True, check=True)
    assert sorted(map(int, result.stdout.split())) == [0, 1, 2, 3]
