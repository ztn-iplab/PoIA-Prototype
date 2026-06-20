# Track A Pre-registration: Attack Success and Functional Correctness

Status: pre-registered; no Track A validation trials have been run under this protocol.

Pre-registration date: 2026-06-20 (Asia/Tokyo)

Controlling protocol: `PoIA_Experimental_Validation_Plan.pdf`, archived locally with the manuscript at `PoIA_Extended/PoIA_Experimental_Validation_Plan.pdf`.

Controlling protocol SHA-256: `3fa47df0a9253156b2faef6312f392425604c15050f0dd1049b861f00246e185`.

## 1. Claims and Manuscript Targets

This track supplies evidence for the manuscript's attack-success matrix, PoIA rejection-reason table, and authorization-correctness table.

Primary claim: a valid session, bearer token, service credential, or proof for a different operation is insufficient to execute a PoIA-protected operation. Execution requires a fresh proof whose canonical intent matches the exact action, scope, principal, context, validity constraints, and workflow semantics of the requested operation.

Secondary claim: correctly formed legitimate operations are accepted, while malformed, stale, replayed, context-mismatched, and semantically mutated operations are rejected without a protected state transition.

## 2. Frozen Independent Variables

Authorization configurations:

1. `session_only`
2. `poia_webauthn`
3. `poia_zt_authenticator`

Attack scenarios:

1. `replay`
2. `relay_phishing`
3. `session_hijacking_or_misuse`
4. `request_tampering`
5. `token_reuse`
6. `confused_deputy`
7. `multi_step_abuse`

Functional-correctness categories:

1. Exact legitimate match
2. Action mismatch
3. Scope mismatch, including partial-field currency tampering
4. Context or relying-party mismatch
5. Principal mismatch
6. Nonce mismatch and nonce reuse
7. Expired intent
8. Validity-boundary submission at `T+59.9 s` and `T+60.1 s` for a 60-second window
9. Canonical field-order variation with unchanged semantics
10. Encoding and Unicode/locale normalization cases
11. Target-object mismatch
12. Workflow-identifier mismatch

## 3. Sample Sizes

- Attack trials: `n = 200` per attack scenario per authorization configuration.
- Functional-correctness trials: `n = 200` per category per PoIA signing backend unless a category is backend-independent and explicitly identified as verifier-only.
- Legitimate-path sanity checks are run before attack trials and reported separately; they are not included in attack-success denominators.
- Runs will be split into independently identified batches. Batch size and dates will be recorded before execution.

No sample-size reduction or early stopping is permitted after observing outcomes. Any infeasible cell will remain explicitly missing and will be described as not measured.

## 4. Dependent Variables

Primary variables:

- protected operation executed: boolean
- authorization decision: `accept` or `reject`
- expected decision: `accept` or `reject`
- rejection reason
- unauthorized database state transition: boolean

Secondary variables:

- challenge-to-decision latency in milliseconds
- signing backend
- proof identifier
- nonce identifier and pre/post consumption state
- canonical intent hash
- request identifier
- workflow identifier where applicable
- relying-party/verifier commit
- authenticator commit and dirty-state indicator
- scenario definition version
- batch identifier and attempt number

## 5. Operational Definitions

An attack succeeds only when the mutated or unauthorized protected operation produces its prohibited state transition. A `2xx` response without the prohibited state transition is not counted as attack success, but is recorded as an implementation anomaly. A rejection response after a prohibited state transition is counted as attack success and a critical atomicity failure.

A false acceptance occurs when an operation expected to be rejected executes. A false rejection occurs when an exact, fresh, valid, policy-permitted operation is denied.

The denominator includes every issued attempt except trials invalidated by a documented harness failure that occurs before the request reaches the relying party. Application errors, verifier errors, timeouts after receipt, and malformed server responses are not silently excluded; they are retained as separate outcomes and included in sensitivity reporting.

## 6. Statistical Treatment

For every binary result, report the observed count and proportion with a two-sided Wilson 95% confidence interval. Bare `0%` and `100%` values are prohibited.

For latency, report `n`, median, IQR, P95, and P99 from raw per-request timestamps. Security decisions and latency are analyzed separately so an attack rejection is not treated as a successful authorization latency observation.

No null-hypothesis significance test is planned for deterministic verifier correctness. Comparative attack proportions will be presented with confidence intervals and absolute count differences. Any later statistical test must be labeled exploratory unless this file is amended and committed before the affected trials begin.

## 7. Scenario Randomization and Seeds

Security-relevant mutations are fixed by declarative scenario definitions. Irrelevant values such as synthetic account identifiers, amounts within allowed ranges, resource identifiers, and request ordering will be generated from recorded seeds.

The harness must write the seed into every run manifest. A failed trial must be reproducible from its scenario file, seed, attempt number, and commit identifiers.

## 8. Required Evidence per Attempt

Each attempt must produce or reference:

- declarative scenario file
- original request and mutated request
- structured JSONL verifier decision
- nonce-state evidence
- audit entry
- pre/post protected-state snapshot
- raw timing record
- signing-backend record
- request identifier linking all artifacts

Track E network captures are separate companion evidence and are not required to begin Track A, but Track A identifiers must be designed so packet captures can be joined later.

## 9. Required Decision Log Schema

```text
timestamp_utc
run_id
batch_id
attempt_n
request_id
scenario_id
scenario_category
configuration
signing_backend
principal
action
scope
context
workflow_id
nonce
proof_id
canonical_intent_hash
expected_decision
decision
rejection_reason
http_status
state_changed
latency_ms
rp_commit
authenticator_commit
scenario_commit
random_seed
```

Sensitive cookies, bearer tokens, private keys, authenticator secrets, and raw personally identifying data must never be written to public artifacts.

## 10. Pre-run Frozen Environment

Relying-party repository:

- repository: `ztn-iplab/PoIA-Prototype`
- pre-registration commit: `95749c9a871752cf934879b264a9be7ae4565cea`
- status at pre-registration: clean

ZT-Authenticator repository:

- observed commit: `fa9c74cdc0476cf1feeefbbff1532f2a30152d06`
- status at pre-registration: dirty; contains uncommitted local changes
- rule: no reportable ZT-Authenticator trial may begin until an experiment commit is created or the exact patch and tree hash are archived in the run manifest

Host summary, excluding device identifiers:

- model: MacBook Air (MacBookAir10,1)
- processor: Apple M1, 8 cores
- memory: 16 GB
- operating system: macOS 26.5.1, build 25F80

Network RTT, container runtime, browser/WebAuthn platform, ZT-Authenticator runtime, database backend, and clock source remain to be measured and frozen in the first run manifest.

## 11. Build Requirements Before Trial 1

The following are prerequisites, not assumed capabilities:

1. Declarative scenario loader and versioned scenario files.
2. Swappable `session_only`, `poia_webauthn`, and `poia_zt_authenticator` gates.
3. Structured JSONL decision logging with request-level linkage.
4. Protected-state pre/post inspection.
5. A downstream service and explicit propagation path for confused-deputy testing.
6. An explicit `on_behalf_of` or equivalent service-delegation field if required by the design discovered during implementation.
7. An explicit `workflow_id` field and verifier behavior for multi-step testing.
8. A controllable clock for precise validity-boundary tests; wall-clock waiting is not required if the same production comparison logic is exercised through an injected clock.
9. Real WebAuthn and ZT-Authenticator approval paths instrumented without replacing their security decision with a software-signing shortcut.
10. A run manifest that freezes commits, configuration, tool versions, random seeds, environment, and output locations.

## 12. Interpretation Rules

- A non-zero PoIA attack-success count is reported and investigated, not removed.
- If confused-deputy or multi-step protection requires a protocol change, the pre-change failure and post-change result are both retained.
- Backend-independent verifier-only tests must not be described as real WebAuthn or ZT-Authenticator measurements.
- Earlier 60-trial and synthetic experiments are pilot evidence and are not merged into this track's confirmatory dataset.
- Results will be inserted into the manuscript only from archived raw data using a versioned analysis script.

## 13. Planned Outputs

```text
experiments/track_a/
  README.md
  manifests/
  scenarios/
  raw/
  decisions/
  state_snapshots/
  analysis/
  tables/
  figures/
```

The final Track A report must map every manuscript value to a run manifest, raw file, analysis command, and commit.
