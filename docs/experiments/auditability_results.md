# Experiment 5: Auditability Results

## Confirmatory Run

- Run ID: `auditability-confirmatory-01`
- Frozen implementation commit: `874a5473d4152a36e276c46267fd7c5c387d411f`
- Paired incidents: 200
- Reconstruction records: 400
- Field-level scores: 2,800

Each synthetic incident produced a baseline session log and a PoIA log. An
automated auditor reconstructed principal, action, scope, time, context, proof,
and execution or denial rationale, then compared each field with independent
ground truth.

## Results

| Log type | Exact completeness | Ambiguity | Missing evidence | Incorrect fields | Median parser time | P95 parser time |
|---|---:|---:|---:|---:|---:|---:|
| Baseline session | 42.86% | 28.57% | 28.57% | 0 | 0.024250 ms | 0.027551 ms |
| PoIA | 100.00% | 0.00% | 0.00% | 0 | 0.064959 ms | 0.073170 ms |

The baseline exactly identified principal, route-level action, and time. Its
session-only context and generic status message were ambiguous, while exact
scope and operation-specific proof were missing. PoIA supplied exact evidence
for all seven fields in every incident. Its richer record took approximately
0.041 ms more at the median to reconstruct and compare.

## Interpretation

This result supports improved structured evidentiary completeness, not faster
human investigation. Timing measures deterministic machine parsing and ground-
truth comparison only. The experiment does not test log tampering, distributed
clock correlation, retention failures, SIEM ingestion, or human auditor
performance. Sanitized proof references are evidence links, not retained
reusable cryptographic assertions.

## Reproduction

```bash
python scripts/run_auditability_experiment.py \
  --run-id auditability-confirmatory-reproduction-01
```

The runner requires a clean tree and exactly 200 paired incidents. Verify the
checksum file and inspect the manifest, JSONL ground truth and logs, field-score
CSV, and incident-score CSV before citing the summary.
