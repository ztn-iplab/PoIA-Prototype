#!/usr/bin/env bash
# Reproduce the lifecycle and independent-root experiments.
#
#   ./scripts/run_experiments.sh              # use ./.venv, create it if absent
#   PY=python3.10 ./scripts/run_experiments.sh
#
# Run it from the repository root. It creates a virtual environment, installs
# the pinned requirements into it, and runs both harnesses with the interpreter
# from that environment -- never a shell-activated one, because an activate
# script records the path the environment was created at and silently falls
# back to the system interpreter once the directory has moved.
#
# The manuscript's Table 5 declares aarch64, Linux 6.8.0, glibc 2.35 and
# CPython 3.10.12. Counts are deterministic and reproduce anywhere; latencies
# do not, so figures quoted in the paper should come from that configuration.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
PY="${PY:-python3}"
VENV="${VENV:-$REPO/.venv}"
TRIALS="${TRIALS:-300}"
MUTATION_TRIALS="${MUTATION_TRIALS:-50}"

echo "repository     : $REPO"
echo "interpreter    : $($PY --version 2>&1) at $(command -v "$PY")"
echo "platform       : $(uname -m), $(uname -s) $(uname -r)"
if command -v ldd >/dev/null 2>&1; then echo "libc           : $(ldd --version 2>/dev/null | head -1)"; fi

case "$($PY -c 'import sys;print("%d.%d"%sys.version_info[:2])')" in
  3.1[0-3]) ;;
  *) echo "WARNING: the pinned requirements have wheels for CPython 3.10-3.13;" >&2
     echo "         a newer interpreter may try to build them from source." >&2 ;;
esac

# A virtual environment holding only pip means the requirements were never
# installed; treat that the same as one that does not exist.
if [ ! -x "$VENV/bin/python" ] || ! "$VENV/bin/python" -c 'import cryptography' >/dev/null 2>&1; then
  echo
  echo "== preparing $VENV"
  [ -x "$VENV/bin/python" ] || "$PY" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -r "$REPO/requirements.txt"
fi
VPY="$VENV/bin/python"
echo "environment    : $($VPY --version 2>&1)"
"$VPY" -c 'import fastapi, cryptography, fido2; print("dependencies   : ok")'

echo
echo "== E6: lifecycle resilience (referent substitution, injected-report roots)"
PYTHONPATH="$REPO" "$VPY" scripts/run_lifecycle_resilience_harness.py \
  --trials "$TRIALS" --out-dir experiments/lifecycle_resilience >/dev/null

echo "== E6b: independent commitment roots (source compromise, no injection)"
PYTHONPATH="$REPO" "$VPY" scripts/run_independent_root_harness.py \
  --trials "$TRIALS" --mutation-trials "$MUTATION_TRIALS" \
  --out-dir experiments/independent_root >/dev/null

echo
"$VPY" - <<'PYEOF'
import json, pathlib
life = json.loads(pathlib.Path("experiments/lifecycle_resilience/lifecycle_resilience_summary.json").read_text())
e6b  = json.loads(pathlib.Path("experiments/independent_root/independent_root_summary.json").read_text())

r, c = life["referent_substitution"], life["commitment_root_compromise"]
print("E6  referent substitution : legacy accepts %.0f%%, strengthened rejects %.0f%%"
      % (r["legacy_gate_acceptance_rate_on_mutated_referent"]*100, r["strengthened_gate_rejection_rate"]*100))
effective = 1.0 - c["fraction_trials_compromised_value_coincided_with_honest_report"]
print("E6  injected-report roots : single-root accepts %.0f%%, two-root rejects %.0f%% of the %.0f%% effective substitutions"
      % (c["k1_legacy_gate_acceptance_rate_of_adversarial_value"]*100,
         c["k2_strengthened_gate_rejection_rate"]/effective*100, effective*100))

for key, label in (("independent_sourcing_arm", "E6b independent roots    "),
                   ("shared_dependency_arm",    "E6b shared upstream      ")):
    a = e6b[key]
    print("%s: %d attacks, %.1f%% accepted, %.1f%% of paired controls accepted"
          % (label, a["attempts"], a["attack_acceptance_rate"]*100, a["paired_control_acceptance_rate"]*100))

cost = e6b["gate_cost_by_configuration"]
print("E6b gate cost            : %.3f ms in process, %.3f ms across processes (median of %d x %d trials)"
      % (cost["median_gate_latency_ms_inprocess"], cost["median_gate_latency_ms_separate_process"],
         cost["repetitions"], cost["trials_per_repetition"]))

ctl = e6b["harness_controls"]
print("E6b harness controls     : forced-agreement %.0f%%, forced-disagreement %.0f%%, offline root fails closed %s"
      % (ctl["forced_agreement"]["acceptance_rate"]*100, ctl["forced_disagreement"]["acceptance_rate"]*100,
         ctl["root_b_offline"]["fails_closed"]))
print("\nwritten to experiments/lifecycle_resilience/ and experiments/independent_root/")
PYEOF
