# PoIA Experiment Reproducibility Guide

This directory explains the journal experiment package for the PoIA prototype.
The scripts in `scripts/` generate the data, but the purpose of this guide is
to make the experiment design understandable and reproducible without treating
the code as a black box.

## Research Claim

The experiment suite supports the claim that Proof-of-Intent Authentication
(PoIA) is a general authorization model that enforces Intent Integrity across
attack patterns, application domains, and deployment settings with predictable
cost.

In these experiments, Intent Integrity means that a high-risk operation is
executed only when the proof presented to the relying party matches the exact
user-approved intent:

```text
user + action + object/scope + relying-party context + nonce + validity window
```

## Reproducibility Layout

Run all commands from the repository root:

```bash
cd path/to/poia-prototype
```

Generated artifacts are stored under `experiments/`. Each experiment directory
contains machine-readable data (`.json` and `.csv`) and a paper-friendly
Markdown result table (`*_table.md`).

The scripts are dependency-light and deterministic enough for local reruns. The
reported latencies are local measurements, so absolute timing values may vary by
machine, but the security/correctness decisions should remain stable.

## Experiment Index

| No. | Experiment | Script | Main Output |
|---:|---|---|---|
| 1 | Security effectiveness expansion | `scripts/run_security_effectiveness_expanded.py` | `experiments/security_effectiveness_expanded/` |
| 2 | Functional correctness stress test | `scripts/measure_functional_correctness.py` | `experiments/functional_correctness_stress/` |
| 3 | Performance and scalability | `scripts/measure_performance_scalability.py` | `experiments/performance_scalability/` |
| 4 | Signing backend comparison | `scripts/compare_signing_backends.py` | `experiments/signing_backend_comparison/` |
| 5 | Auditability | `scripts/run_auditability_experiment.py` | `experiments/auditability/` |
| 6 | Cross-domain generality | `scripts/run_cross_domain_generality.py` | `experiments/cross_domain_generality/` |
| 7 | OAuth/API integration | `scripts/run_oauth_api_integration.py` | `experiments/oauth_api_integration/` |
| 8 | Formal verification expansion | `scripts/generate_formal_verification_artifacts.py` and `tamarin/poia_protocol.spthy` | `experiments/formal_verification_expansion/` |
| 9 | Usability-light structured analysis | `scripts/run_usability_structured_analysis.py` | `experiments/usability_structured/` |
| 10 | Sensitivity analysis | `scripts/run_sensitivity_analysis.py` | `experiments/sensitivity_analysis/` |

## One-by-One Reproduction Commands

```bash
python3 scripts/run_security_effectiveness_expanded.py --trials 60 --out-dir experiments/security_effectiveness_expanded
python3 scripts/measure_functional_correctness.py --trials 60 --out-dir experiments/functional_correctness_stress
python3 scripts/measure_performance_scalability.py --loads 1,10,50,100,200 --ops-per-user 20 --out-dir experiments/performance_scalability
python3 scripts/compare_signing_backends.py --trials 100 --out-dir experiments/signing_backend_comparison
python3 scripts/run_cross_domain_generality.py --trials 60 --out-dir experiments/cross_domain_generality
python3 scripts/run_auditability_experiment.py --events 120 --out-dir experiments/auditability
python3 scripts/run_oauth_api_integration.py --trials 60 --out-dir experiments/oauth_api_integration
python3 scripts/generate_formal_verification_artifacts.py --out-dir experiments/formal_verification_expansion --run-tamarin
python3 scripts/run_usability_structured_analysis.py --out-dir experiments/usability_structured
python3 scripts/run_sensitivity_analysis.py --trials 10 --out-dir experiments/sensitivity_analysis
```

## How to Read the Results

For each experiment, start with the Markdown table. Then inspect the summary JSON
for exact aggregate values. Use the CSV trial files when you need trial-level
evidence for reviewer responses or appendix material.

Typical reading order:

1. Open `experiments/<experiment>/<experiment>_table.md`.
2. Open the matching `*_summary.json` to confirm metrics and parameters.
3. Open the matching `*_trials.csv` to inspect individual decisions.
4. Rerun the command above and compare the newly generated outputs.

## Important Modeling Notes

These experiments include both prototype-driven and simulation-style evidence:

- Experiments 1, 2, 6, 7, 9, and 10 are controlled simulations of PoIA semantics.
- Experiment 3 measures local cryptographic and serialization costs, with user
  interaction delay modeled separately.
- Experiment 4 compares signing backends using the same intent proof interface.
- Experiment 8 is a symbolic model in Tamarin and should be inspected separately
  from the Python experiments.

The simulations are not meant to claim that every real-world OAuth server,
banking application, or healthcare system behaves exactly like these examples.
They isolate the authorization question: what happens when a valid session or
token is reused for a different high-risk intent?

## Deep Dives

- `docs/experiments/experiment_designs.md` explains each experiment's research
  question, implementation, metrics, and interpretation.
- `docs/experiments/oauth_api_integration.md` explains Experiment 7 in detail.
- `docs/experiments/tamarin_formal_verification.md` explains the Tamarin model,
  lemmas, and interactive testing workflow.
