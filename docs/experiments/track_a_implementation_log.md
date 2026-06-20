# Track A Implementation Log

This log records protocol-relevant implementation changes after the Track A
pre-registration. It is not a results table.

## Atomic proof consumption

Date: 2026-06-20

Pre-change finding: `A-IMPL-001` in `track_a_gap_audit.md` identified that an
approved proof remained approved after protected execution. Repeated calls to
the execution endpoint could therefore pass the same authorization check.

Implemented state machine:

```text
pending --verified backend proof--> approved --execution reservation--> consumed
   |                                  |
   +------------ denial ------------+ +-- expiry/replay/principal mismatch --> reject
```

The relying party now reserves execution through
`InMemoryPoIA.reserve_execution()`. The check and the transition from
`approved` to `consumed` occur under the same re-entrant lock. The transition
happens before dispatch to the protected banking operation.

This ordering has two intentional consequences:

1. At most one concurrent request can obtain execution authority.
2. A business-level failure, such as insufficient funds, does not reopen the
   proof. A new operation requires a new intent and proof.

The in-memory lock protects one Python process only. It is appropriate for the
pre-registered single-process Track A correctness configuration, but it is not
evidence of multi-worker or distributed atomicity. Track C must evaluate a
shared transactional nonce/proof backend separately.

Backend approval is also installed through `approve_proof()`. This prevents a
late verified response or duplicate backend response from overwriting a proof
that has already left `pending` state.

### Rejection taxonomy

- `intent_invalid`: intent or challenge does not exist.
- `principal_mismatch`: session principal differs from the intent principal.
- `proof_missing`: no proof state exists.
- `proof_not_approved`: proof is pending or denied.
- `proof_consumed`: an execution reservation already consumed the proof.
- `expired`: the challenge validity deadline has passed.
- `replay`: a backend tries to install another approval after the proof left
  pending state.

### Verification performed

`tests/test_poia_state_machine.py` exercises:

- 200 concurrent execution reservations, expecting exactly one acceptance and
  199 `proof_consumed` rejections;
- repeated execution after consumption;
- approval after exact floating-point expiry;
- wrong-principal rejection without accidental proof consumption.

The complete local unit suite passed 11 tests after this change. Route-level
application startup was not validated in this shell because FastAPI is not
installed and Docker is unavailable. That limitation must be cleared before a
confirmatory run and must not be represented as successful end-to-end testing.

## Manifest-bound evidence recording

Date: 2026-06-20

The execution gate now activates a confirmatory recorder only when
`POIA_TRACK_A_MANIFEST` identifies a prepared run. Every completed execution
attempt writes:

- one append-only JSONL decision matching the preregistered field contract;
- one linked pre/post protected-state snapshot;
- a request identifier and unique attempt number;
- authorization latency measured with a monotonic high-resolution clock;
- the frozen RP, authenticator, scenario, configuration, and seed metadata;
- hashed nonce, proof, principal, account, and sensitive target identifiers.

For manual browser sessions, attempt numbers increment automatically. A harness
can provide explicit request, attempt, scenario, category, and expected-decision
headers. Recording refuses to start when the scenario or expected decision is
unspecified, preventing unlabeled observations from entering the dataset.

`scripts/analyze_track_a.py` generates interim tables on demand and final tables
only at exactly 200 uniquely numbered decisions. Binary outcomes include
two-sided Wilson 95% confidence intervals. Latency is reported separately as
median, IQR, P95, and P99.

### Verification performed

The pinned application dependencies were installed in a temporary environment.
The complete FastAPI application imported with 81 routes. An HTTP regression
test then executed an approved transfer twice through the real execution route:

- first request: accepted, one transfer inserted, balance changed once, linked
  decision and snapshot written;
- second request: rejected with `proof_consumed`, no additional transaction or
  balance change, linked decision and unchanged snapshot written.

The dependency-backed suite passed 19 tests. The standard-library suite also
passed, with the HTTP test explicitly skipped when optional application test
dependencies are unavailable.

## Explicit semantic comparison path

Date: 2026-06-20

The atomic execution gate accepts an optional requested intent and compares it
to the approved intent before consuming the proof. The rejection taxonomy now
distinguishes action, scope, principal, relying-party, workflow, delegation,
context, and constraint mismatches. A mismatch leaves the proof approved, so a
subsequent exact request can still be tested without conflating tampering with
proof consumption.

An authenticated endpoint at `/api/poia/experiment/execute` exposes this exact
production state transition only when `POIA_EXPERIMENT_MODE=true`. It currently
dispatches real transfer execution after a successful match. Reportable runs
must keep `POIA_TEST_MODE=false`; experiment mode does not bypass proof
verification or approval.

Every recorded attempt now includes a separate redacted request artifact with
the approved and requested intents. This supplies the preregistered original-
versus-mutated evidence without storing direct account numbers, external
targets, user identifiers, nonces, proofs, or signatures.

The HTTP regression was expanded to submit an approved amount of 100 and a
requested amount of 700. The endpoint returned `scope_mismatch`, inserted no
transaction, changed no balance, retained the proof in approved state, and
wrote the paired request artifact. Both test modes passed 21 tests.

## Multi-step workflow binding

Date: 2026-06-20

The lab workflow-start endpoint creates a database-backed pending workflow that
binds a synthetic principal, action, and canonical scope digest. The generated
PoIA intent carries the same `workflow_id`. Execution requires the semantic
intent match and a pending workflow with the matching principal, action, and
scope; successful reservation consumes the workflow once before dispatch.

The HTTP regression first substituted a different workflow identifier. The
request was rejected as `workflow_mismatch`, with no proof consumption,
workflow consumption, transfer, or balance change. The exact approved request
then executed one transfer and changed the workflow to `consumed`. This is the
executable basis for the `multi_step_abuse` cell; it is not yet an `n=200`
confirmatory result.
