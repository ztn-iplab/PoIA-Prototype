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
