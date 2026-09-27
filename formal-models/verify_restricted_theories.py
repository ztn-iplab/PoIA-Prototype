#!/usr/bin/env python3
"""Reproduce the referent, commitment and composition-pipeline results.

Runs the three restricted theories, writes a log beside each one, checks every
lemma against the outcome the manuscript reports, and records commands,
outcomes and file hashes in proofs/restricted_theories_manifest.json.

Exit status is non-zero unless all twelve obligations come out as expected, so
a silent regression cannot pass.

    python3 formal-models/verify_restricted_theories.py

Tamarin 1.12.0 / Maude 3.5.1. These theories need no oracle: their results are
independent of the proof heuristic.
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# theory file -> {lemma: expected outcome}, exactly as Table 5 reports them.
EXPECTED = {
    "referent_state_integrity.spthy": {
        "legacy_executable": "verified",                        # non-vacuity
        "rsi_executable": "verified",                           # non-vacuity
        "legacy_vulnerable_to_referent_substitution": "verified",
        "rsi_accept_uses_committed_version": "verified",
    },
    "kofn_confinement.spthy": {
        "k1_executable": "verified",                            # non-vacuity
        "k2_executable": "verified",                            # non-vacuity
        "k1_vulnerable_to_single_root_compromise": "verified",
        "k2_resists_single_root_compromise": "verified",
        "k2_never_signs_substituted_value": "verified",
    },
    "full_lifecycle_non_reconstitution.spthy": {
        "pipeline_executable": "verified",                      # non-vacuity
        "full_lifecycle_non_reconstitution": "verified",
        "weak_pipeline_vulnerable_to_single_compromise": "verified",
    },
}

LEMMA_LINE = re.compile(
    r"^\s*([A-Za-z0-9_]+)\s*\((all-traces|exists-trace)\)\s*:\s*(verified|falsified)"
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def outcomes(log_text):
    """Lemma results from Tamarin's summary-of-summaries block."""
    tail = log_text.split("summary of summaries", 1)[-1]
    found = {}
    for line in tail.splitlines():
        m = LEMMA_LINE.match(line)
        if m:
            found[m.group(1)] = {"kind": m.group(2), "result": m.group(3)}
    return found


def main():
    if shutil.which("tamarin-prover") is None:
        sys.exit("tamarin-prover not on PATH")

    version = subprocess.run(
        ["tamarin-prover", "--version"], capture_output=True, text=True
    ).stdout.strip()

    results, failures = [], []
    for name, expected in EXPECTED.items():
        theory = HERE / name
        if not theory.exists():
            sys.exit("missing theory: %s" % theory)
        log = theory.with_suffix(".log")
        cmd = ["tamarin-prover", "--prove", "--quit-on-warning", str(theory)]

        print("== %s" % name, flush=True)
        started = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = round(time.time() - started, 1)
        log.write_text(proc.stdout + proc.stderr, encoding="utf-8")

        got = outcomes(log.read_text(encoding="utf-8"))
        for lemma, want in expected.items():
            have = got.get(lemma, {}).get("result")
            ok = have == want
            print("   %-46s %-9s %s" % (lemma, have or "MISSING", "ok" if ok else "MISMATCH"))
            if not ok:
                failures.append("%s: %s expected %s, got %s" % (name, lemma, want, have))
        for lemma in got:
            if lemma not in expected:
                failures.append("%s: unexpected lemma %s in output" % (name, lemma))

        results.append({
            "theory": name,
            "sha256": sha256(theory),
            "command": cmd,
            "log": log.name,
            "seconds": elapsed,
            "expected": expected,
            "outcomes": got,
        })
        print("   (%ss)" % elapsed, flush=True)

    manifest = HERE / "proofs" / "restricted_theories_manifest.json"
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({
        "tamarin_version": version,
        "oracle_used": False,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "all_expected": not failures,
        "results": results,
    }, indent=2) + "\n", encoding="utf-8")

    print("\nmanifest: %s" % manifest)
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        return 1
    print("all 12 obligations matched the reported outcomes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
