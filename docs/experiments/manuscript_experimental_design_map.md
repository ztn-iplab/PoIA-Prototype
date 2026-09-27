# Manuscript Experimental-Design Evidence Map

> **Note on paths in this directory.** Documents here describe the experiment
> designs and the runs recorded at the time of writing. Result packages named
> after superseded runs were removed in the 2026-09-10 evidence reset and are
> not in this repository; `REPRODUCTION.md` lists the packages the manuscript
> actually reports and the runner that regenerates each one.

This file maps the experimental-design section in `PoIA_Extended/Main.tex` to
the reproducible repository artifacts. The manuscript directory is local and
ignored; this map is the versioned trace record for the section.

## Study Protocol

- Controlling plan: `PoIA_Experimental_Validation_Plan.pdf`
- Pre-registration: `docs/experiments/track_a_preregistration.md`
- Real-backend operator protocol:
  `docs/experiments/track_a_real_backend_protocol.md`

## Track A

- Scenario corpus: `experiments/track_a/scenarios/security_effectiveness.json`
- Functional corpus: `experiments/track_a/scenarios/functional_correctness.json`
- Manifest and evidence utilities: `scripts/track_a_evidence.py`
- Manifest-bound recorder: `app/track_a_recorder.py`
- Progress validation: `scripts/track_a_run_status.py`
- Statistical analysis: `scripts/analyze_track_a.py`
- Verifier-only result: `docs/experiments/track_a_functional_results.md`
- Real WebAuthn and ZT results: pending 200-operation production-path runs
- ZT hash-interoperability diagnostic and exclusion rationale:
  `docs/experiments/zt_intent_hash_incident.md`
- Cross-client canonicalization vector:
  `experiments/protocol_vectors/zt_intent_hash_v1.json`

The verifier-only result must remain separate from authenticator interaction,
signature-generation, interoperability, and end-to-end latency claims.

## Extended Attack Paths

- Bearer-token cross-action reuse: `app/routes/poia.py` and
  `tests/test_token_reuse_http.py`
- Confused-deputy downstream enforcement: `app/downstream_client.py`,
  `downstream/main.py`, and `tests/test_downstream_ledger_http.py`
- Multi-step workflow binding: `app/routes/poia.py` and the Track A scenario
  corpus
- Atomic proof consumption and replay: `app/poia.py` and
  `tests/test_poia_execution_http.py`

## Tracks B-C

- Detailed designs: `docs/experiments/experiment_designs.md`
- Track B pre-registration: `docs/experiments/track_b_preregistration.md`
- Track B executable gates: `app/authorization_baselines.py`
- Track B scenario corpus:
  `experiments/track_b/scenarios/comparative_baselines.json`
- Track B runner and reproduction guide:
  `scripts/run_track_b_comparative.py` and `experiments/track_b/README.md`
- Track B confirmatory results: `docs/experiments/track_b_results.md`, with the
  reviewed manifest, summary, table, and checksums under `experiments/track_b/`.
- Track C measurements are reportable only when a clean, fixed run manifest
  and reviewed raw archive are cited.
- Track C1 pre-registration: `docs/experiments/track_c_preregistration.md`
- Track C1 runner and reproduction guide:
  `scripts/run_track_c_performance.py` and `experiments/track_c/README.md`
- Track C1 confirmatory results: `docs/experiments/track_c_results.md`, with
  reviewed manifest, summary, table, and checksums under `experiments/track_c/`.
- Track C2 distributed placement/fault injection and real-authenticator
  end-to-end latency must not be inferred from C1.
- Track C2 pre-registration and runner:
  `docs/experiments/track_c2_preregistration.md` and
  `scripts/run_track_c_distributed.py`
- Track C2 confirmatory results: `docs/experiments/track_c2_results.md`, with
  reviewed artifacts under `experiments/track_c/`.
- Real-authenticator end-to-end latency remains pending the 200-operation runs.

## Track D

- Model: `tamarin/poia_protocol.spthy`
- Pre-registration: `docs/experiments/track_d_preregistration.md`
- Reproduction guide: `docs/experiments/tamarin_formal_verification.md`
- Runner: `scripts/run_tamarin_poia.sh`
- Manifest-bound artifact generator:
  `scripts/generate_formal_verification_artifacts.py`
- Confirmatory result: `docs/experiments/track_d_results.md` and
  `experiments/formal_verification_expansion/track-d-confirmatory-02-*`

## Cross-Domain Generality

- Pre-registration: `docs/experiments/cross_domain_preregistration.md`
- Shared-verifier runner: `scripts/run_cross_domain_generality.py`
- Regression test: `tests/test_cross_domain_generality.py`
- Confirmatory result: `docs/experiments/cross_domain_results.md`
- Manifest, raw decisions, summary, table, and checksums:
  `experiments/cross_domain_generality/cross-domain-confirmatory-01-*`

This experiment is controlled schema-level evidence. It must not be described
as deployment of four complete production platforms or as real-authenticator
end-to-end latency.

## Auditability

- Pre-registration: `docs/experiments/auditability_preregistration.md`
- Paired reconstruction runner: `scripts/run_auditability_experiment.py`
- Scoring regression: `tests/test_auditability_experiment.py`
- Confirmatory result: `docs/experiments/auditability_results.md`
- Ground truth, paired logs, field and incident scores, manifest, summary,
  table, and checksums:
  `experiments/auditability/auditability-confirmatory-01-*`

Reconstruction latency is automated parser and comparison cost. It is not a
measurement of human investigation time.

## OAuth/API Integration

- Pre-registration: `docs/experiments/oauth_api_preregistration.md`
- Route and evidence explanation: `docs/experiments/oauth_api_integration.md`
- HTTP/SQLite runner: `scripts/run_oauth_api_integration.py`
- Route regression: `tests/test_token_reuse_http.py`
- Harness regression: `tests/test_oauth_api_runner.py`
- Confirmatory result: `docs/experiments/oauth_api_results.md`
- Manifest, redacted trials, summary, table, and checksums:
  `experiments/oauth_api_integration/oauth-api-confirmatory-01-*`

This is resource-server integration evidence using broad bearer-token semantics
and an in-process approved-proof fixture. It is not OAuth conformance or real-
authenticator evidence.

## Structured Prompt Analysis

- Pre-registration: `docs/experiments/usability_structured_preregistration.md`
- Construct-validity amendment:
  `docs/experiments/usability_structured_amendment.md`
- Manifest-bound runner: `scripts/run_usability_structured_analysis.py`
- Regression test: `tests/test_usability_structured_analysis.py`
- Confirmatory result: `docs/experiments/usability_structured_results.md`
- Field rows, substitution rows, summary, table, manifest, and checksums:
  `experiments/usability_structured/usability-structured-confirmatory-05-*`

This is deterministic approval-content coverage, not a participant study. It
must not be used to claim comprehension, confusion rate, approval time, or
habituation outcomes. Runs `usability-structured-confirmatory-02` and
`usability-structured-confirmatory-03` are preserved, superseded diagnostics
and are excluded from manuscript findings.

## Sensitivity Analysis

- Pre-registration: `docs/experiments/sensitivity_analysis_preregistration.md`
- Manifest-bound runner: `scripts/run_sensitivity_analysis.py`
- Regression test: `tests/test_sensitivity_analysis.py`
- Confirmatory result: `docs/experiments/sensitivity_analysis_results.md`
- Expiry-policy rows, compute rows, concurrency rows, summary, table, manifest,
  and checksums:
  `experiments/sensitivity_analysis/sensitivity-confirmatory-01-*`

Modeled arrival delay is not measured network latency, and configured validity
is not an observed replay-success duration. This local microbenchmark remains
separate from Track C and real-authenticator end-to-end measurements.

## Network-capture exercise (not part of this release)

A red-team and packet-capture exercise against a deployed instance is future
work. The manuscript makes no claim from it: every adversarial result reported
is a controlled semantic-effect test against the verifier, not an observation of
live malware. No such result may be inferred from the unit tests or synthetic
requests in this repository.
