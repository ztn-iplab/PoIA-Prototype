# Experiment 5 Pre-registration: Auditability

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Claim Under Test

For the same protected-operation incident, a PoIA authorization record permits
more complete and less ambiguous reconstruction than a conventional
session-authorization record because it records exact intent and proof evidence.

## Paired Incident Corpus

Generate 200 synthetic incidents. Each incident produces two independently
serialized views of the same ground truth:

1. a baseline session-authorization log; and
2. a PoIA authorization log.

The corpus rotates across banking transfer, enterprise role grant, healthcare
record export, and cloud key rotation. It also rotates across execution and the
following denial causes: action, scope, principal, relying-party, nonce, and
expiration mismatch. Identifiers are synthetic and no secret or reusable proof
material is recorded.

## Reconstruction Fields and Scoring

The automated auditor reconstructs seven pre-specified fields: principal,
action, object/scope, time, authorization context, proof evidence, and execution
or denial rationale. Each field is scored against a separate ground-truth record
as:

- exact: one value matching ground truth;
- ambiguous: partial or generic evidence that admits multiple interpretations;
- missing: no evidence for the field; or
- incorrect: a value contradicting ground truth.

Completeness is exact fields divided by seven. Ambiguity rate and missing
evidence rate use the same denominator. Any incorrect reconstruction is reported
separately and invalidates a perfect-completeness claim.

## Timing

Measure automated parsing and comparison time with a monotonic nanosecond clock.
Report median, IQR, P95, and P99. This is machine reconstruction cost and must
not be described as human incident-investigation time. A controlled auditor
study would be required for that claim.

## Confirmatory Controls

- Fixed sample size: 200 paired incidents, 400 reconstruction records.
- Clean Git working tree and unique run identifier required.
- Manifest records commit, runtime, corpus dimensions, and file hashes.
- Raw logs, ground truth, field-level scores, summaries, and SHA-256 checksums
  are preserved.
- Existing unversioned 120-event files are exploratory and excluded.

## Interpretation Limit

The experiment measures evidentiary content and deterministic machine
reconstruction under known log schemas. It does not measure human comprehension,
cross-system clock correlation, retention failure, log tampering, or the quality
of a commercial SIEM deployment.
