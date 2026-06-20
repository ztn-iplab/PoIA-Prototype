# Track A Pre-implementation Gap Audit

Audit date: 2026-06-20 (Asia/Tokyo)

Audited RP commit: `a913bf8` (pre-registration commit), whose implementation parent is `95749c9`.

This audit records implementation facts observed before Track A harness construction. It is not an experimental result and must not be reported as measured attack prevalence. Findings that affect security behavior must be retained as pre-fix evidence and validated explicitly after correction.

## Requirement Matrix

| Track A requirement | Current state | Gap / required action |
|---|---|---|
| Declarative scenario files | Missing | Existing experiment scripts construct scenarios in Python. Add versioned YAML or JSON scenario definitions and schema validation. |
| Session-only configuration | Partial | `POIA_ENABLED=false` bypasses PoIA globally, but the confirmatory harness needs an explicit configuration identity in every decision record and equivalent business logic/state reset. |
| Real WebAuthn path | Present, incompletely instrumented | `/poia/assertion-begin` and `/poia/assertion-complete` use registered WebAuthn credentials. Add request-level timestamps, run identifiers, proof identifiers, and evidence linkage without replacing real authenticator verification. |
| Real ZT-Authenticator path | Present, incompletely frozen | `/api/poia/pending` and `/api/poia/approve` verify enrolled P-256 device signatures. Freeze the dirty ZT repository state before reportable runs and add run/evidence linkage. |
| Structured decision JSONL | Missing | Existing telemetry is CSV and does not include the pre-registered schema, protected-state outcome, commit set, seed, or complete decision linkage. |
| Protected-state snapshots | Missing | Add action-specific pre/post snapshots and a stable comparison digest so rejection-after-side-effect bugs are detectable. |
| Downstream microservice | Missing | The application is a single relying-party service. Add a minimal independently authenticated downstream ledger service and explicit service-to-service propagation path. |
| `on_behalf_of` delegation binding | Missing | No canonical intent field identifies the delegating service or end-user authority propagated to a downstream service. Define only after testing the unextended path and recording the design gap. |
| `workflow_id` binding | Missing | No workflow identifier is present in banking intent context or verifier behavior. Add explicit workflow semantics for beneficiary-to-transfer tests. |
| Controllable clock | Missing | Production code calls `time.time()` directly. Introduce an injectable clock used by the same expiration comparison path for precise `T+59.9` / `T+60.1` tests. |
| Run manifests | Missing | Add machine-readable manifests containing commits, dirty state, environment, tool versions, configuration, seed, and output checksums. |
| Automated state reset | Missing | Confirmatory attempts need deterministic synthetic accounts and transaction/beneficiary reset between trials or isolated databases per batch. |

## Security-Relevant Pre-run Findings

### A-IMPL-001: Approved proof is not atomically consumed at execution

Observed code path:

1. WebAuthn or ZT approval replaces the pending proof with a `ProofRecord(status="approved")`.
2. `GET /poia/execute/{intent_id}` accepts any proof whose status remains `approved` and whose challenge has not expired.
3. The execution handler logs `intent_execute` and performs the state transition.
4. No code changes the proof status to `consumed`, removes the challenge, or atomically reserves the nonce before the state transition.

Consequence to test: repeated or concurrent calls to the execution endpoint may produce repeated state transitions during the validity window. This directly conflicts with the manuscript's single-purpose authorization and atomic nonce-consumption claims.

Required scientific handling:

- Preserve the pre-fix commit and create a diagnostic reproduction with synthetic data.
- If reproduced, report it as a discovered implementation defect, not as an excluded harness error.
- Implement atomic transition from `approved` to `consumed` before protected execution.
- Add rollback/error semantics so failed business execution does not silently permit unsafe replay.
- Run the full replay and concurrent-replay confirmatory cells against the corrected frozen commit.

### A-IMPL-002: The standalone semantic verifier is not used by the execution path

`app/core.py` defines `verify_proof(...)`, including canonical equality and signature checks, but no application route calls it. The real WebAuthn and ZT approval routes perform backend-specific proof checks, while execution uses the stored intent body directly.

Interpretation: direct post-approval mutation of ordinary request parameters cannot affect the stored execution intent, which is a useful design property. However, the manuscript and harness must describe the actual state machine accurately and must not cite the unused helper as evidence that execution performs a fresh semantic comparison.

Required action: define one authoritative authorization service/state transition used by both signing backends and execution. Tests must target that production path.

### A-IMPL-003: In-memory state is process-local and not concurrency-safe

Intent, challenge, and proof records are held in ordinary Python dictionaries. There is no lock, transaction, durable nonce table, or cross-process consistency mechanism.

Consequence: multi-worker deployment, concurrent execution, restart behavior, and distributed nonce consumption are not currently supported by the security state model.

Required action for Track A: use a deterministic single-process test configuration for functional/security correctness, while implementing atomic in-process consumption. Track C will separately introduce and measure durable/shared nonce backends.

### A-IMPL-004: Expiration checks are distributed across routes

Expiration is checked when reading an intent, beginning WebAuthn assertion, approving through ZT-Authenticator, querying status, and executing. WebAuthn assertion completion does not itself reject completion after expiration, although the later execution route checks expiration.

Required action: centralize the final authorization decision so all backends produce the same rejection taxonomy and timing-boundary behavior. The execution gate remains the authoritative protection point.

## Existing Assets We Can Reuse

- Server-side canonical JSON with sorted keys and fixed separators.
- Intent construction and proof-payload hashing.
- Real WebAuthn registration/assertion support.
- Real ZT-Authenticator pending-intent and P-256 approval support.
- Banking transfer, beneficiary, cash, statement-export, and administrative actions.
- SQLite business-state tables suitable for state snapshots.
- Existing pilot scripts and artifact conventions, retained as non-confirmatory references.

## Implementation Order Derived from the Audit

1. Add run manifest and declarative scenario schemas.
2. Add structured JSONL decision/evidence logging and state snapshots.
3. Introduce an authoritative atomic execution gate with `pending -> approved -> consumed` state transitions.
4. Add injectable time and expanded functional tests.
5. Add explicit workflow context and multi-step path.
6. Add downstream service and delegation path for confused-deputy testing.
7. Instrument real WebAuthn and ZT paths and freeze both repositories.
8. Run diagnostic pre-fix replay only as a labeled implementation investigation.
9. Freeze the corrected Track A release and begin confirmatory batches.
