# Reproduction Guide

This is the entry point for checking the results the manuscript reports. It
names, for each reported result, the retained inputs, the implementation the
run exercised, and the runner that regenerates it.

## Scope of each run

The runs differ in what they exercise, and the distinction matters when reading
the numbers:

- Referent-integrity and commitment-confinement trials call those gate
  functions directly.
- Canonicalization, state-machine, robustness and cross-domain experiments
  instantiate the in-memory state machine without the strengthened gates.
- Component and throughput measurements are standalone cryptographic
  benchmarks, not end-to-end authorization.
- Approval latency is measured over 100 approvals per signing backend. The
  selection is recorded in `experiments/live_approval_20260910/final_latency_table.json`
  and applied by `scripts/finalize_latency.py`, whose `--zt-discard` option
  carries it; the complete approval log is released unmodified as
  `experiments/live_approval_20260910/poia_experiments_live.csv`.

## Result, input, runner

| Evidence | Retained inputs / implementation | Runner |
| --- | --- | --- |
| Exact binding | `experiments/manuscript_20260824/scenarios/e1_exact_intent_matching.json` | `scripts/run_manuscript_e1.py` |
| Replay, context, concurrency | `experiments/manuscript_20260824/scenarios/rq2_robustness.json` | `scripts/run_manuscript_rq2.py` |
| Cross-domain schema behaviour | `experiments/manuscript_20260824/scenarios/rq3_cross_domain.json` | `scripts/run_manuscript_rq3.py` |
| Comparative configurations | `experiments/track_b/scenarios/`, `app/authorization_baselines.py` | `scripts/run_track_b_comparative.py` |
| Retained-original safeguard | `app/core.py` | `scripts/run_original_request_binding_experiment.py`; independent check: `scripts/check_original_binding_evidence.py` |
| Referent and commitment gate checks | `app/core.py`, `app/commitment_confinement.py` | `scripts/run_lifecycle_resilience_harness.py` |
| Component sensitivity | Declared CLI parameters | `scripts/run_sensitivity_analysis.py` |
| Verifier throughput | Declared CLI parameters | `scripts/run_verifier_scalability_summary.py` |
| Distributed workflow | `app/downstream_client.py`, `downstream/main.py` | `scripts/run_track_c_distributed.py` |
| Audit reconstruction | Synthetic log fixtures | `scripts/run_auditability_experiment.py` |
| Schema representation | Canonical intent fixtures | `scripts/run_usability_structured_analysis.py` |
| Approval timing | Released approval log | `scripts/analyze_live_approval_timing.py` |
| Symbolic verification | `formal-models/*.spthy` | `formal-models/verify_restricted_theories.py` |

Dates in scenario-directory names identify inputs, not result claims. Use each
runner's `--help` before a new run.

## Harness controls

Three controls test whether the apparatus can report error at all. Each is a
deliberate mutation of the verifier that must produce its prescribed failure:

| Control | Location | Required outcome |
| --- | --- | --- |
| Always accept | `experiments/protocol_vectors/attack_outcomes/_harness_validation/mutation-always-accept/` | 100% false acceptance |
| Always reject | `experiments/protocol_vectors/attack_outcomes/_harness_validation/mutation-always-reject/` | 100% false rejection |
| Normalization disabled | `experiments/functional_correctness_stress/_harness_validation/mutation-no-normalization/` | 66.67% false rejection, exactly the canonical-equivalence cases |

## Notes on the recorded provenance

Commands and file paths inside the proof manifests and logs are relative to the
repository root. They were rewritten from the absolute paths of the machine
that produced them; no outcome, digest or timing was altered. The manifests
also carry a `reference_commit` identifying the development revision each run
was made against; that revision belongs to the pre-release history and is not
part of this repository.

## Integrity checks

These establish file identity. None is a fresh proof search or a
re-measurement.

```bash
sha256sum -c RELEASE_CHECKSUMS.sha256        # every file in the release
python3 scripts/verify_artifact_checksums.py # each package against its own run manifest
python3 scripts/check_journal_evidence.py    # the register below against the tree
```

<!-- evidence-register -->
```json
{
  "empirical_status": "remeasured_2026_09_10",
  "empirical_note": "Results regenerated 2026-09-10. Runs differ in scope: referent-integrity and commitment-confinement trials call those gate functions directly; canonicalization, state-machine, robustness and cross-domain experiments instantiate the in-memory state machine without the strengthened gates; component and throughput measurements are standalone cryptographic benchmarks. Approval latency is measured over 100 approvals per backend, the selection being recorded in experiments/live_approval_20260910/final_latency_table.json.",
  "sources": [
    {"source": "formal-models/proofs/verification_manifest.json", "sha256": "3722c84d713a4720030b6f08d990692874554f12f66f852b57af65eafde1c3b2", "manifest": true}
  ]
}
```
