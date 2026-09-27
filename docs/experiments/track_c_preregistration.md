# Track C Pre-registration: Performance and Scalability

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Scope and Evidence Classes

Track C is divided before confirmatory execution:

- **C1, protocol-path microbenchmark:** deterministic server-side component
  latency and concurrent verifier throughput on the development host.
- **C2, deployment experiment:** gateway/service/shared-verifier placement,
  network overhead, and controlled verifier failure. C2 receives its own run
  manifest and is not inferred from C1.
- **Real-authenticator latency:** the 200 WebAuthn and 200 ZT-Authenticator
  production-path actions are analyzed separately. C1 must not be described as
  physical-authenticator or human interaction latency.

The old `experiments/performance_scalability/` dataset is exploratory and is
not reused in Track C.

## C1 Research Questions

1. What are the distributions of intent construction, canonicalization, proof
   construction, signature generation, signature verification, semantic
   comparison, nonce consumption, audit serialization, and total protocol-path
   latency?
2. How does verifier throughput change at concurrency 1, 10, 50, 100, and 200?
3. How do all-accept, all-reject, and 50/50 mixed workloads differ?
4. What overhead is introduced by a durable SQLite nonce store relative to a
   locked in-memory store on the same host?

## Configurations

- `session_baseline`: HMAC-authenticated session decision with no intent proof.
- `poia_webauthn_p256`: P-256 signature over the SHA-256 PoIA proof challenge,
  matching the prototype's WebAuthn challenge construction. This is software
  cryptography, not a platform-authenticator ceremony.
- `poia_zt_p256`: P-256 signature over the ZT device/RP/nonce-bound PoIA proof
  message used by the prototype. This is software cryptography, not handset
  interaction.

All PoIA configurations use `app.intent_codec.canonical_json` and
`app.core.build_proof_payload`. Keys are generated in memory for the run and
are never written to an artifact.

## Fixed Sample Sizes

- Component decomposition: 500 warm-up operations followed by 5,000 measured
  operations per configuration.
- Throughput: 5,000 verifier decisions per configuration, nonce backend,
  workload, and concurrency cell.
- Concurrency: 1, 10, 50, 100, and 200 worker threads.
- Workloads: all-accept, all-reject, and deterministic 50/50 mixed decisions.
  PoIA rejections use semantic mismatch after a valid signature; the session
  baseline uses an invalid MAC because it has no intent-semantic predicate.
- Nonce backends: locked in-memory and local SQLite with one atomic consume
  transaction per proof.

The runner seed is `20260620`. A cell is invalid if its observed decisions do
not exactly match its generated reference decisions or if any task is missing.

## Metrics and Reporting

Latency uses `time.perf_counter_ns`. Report `n`, median, IQR, P95, and P99 in
milliseconds. Throughput is completed decisions divided by cell wall-clock
seconds. Each cell also reports expected/observed accepts and rejects,
incorrect accepts, incorrect rejects, and errors.

The pre-registered operational threshold is verifier P95 below 20 ms. This is
an engineering threshold for the local server-side path, not a universal SLA.
The saturation point is the first concurrency after which throughput fails to
increase by at least 5% while P95 increases, or the highest tested concurrency
if no such point occurs.

## Artifact Rules

The run manifest records the run ID, repository commit, dirty-tree status,
scenario parameters, host/runtime metadata, and hashes of the runner and this
pre-registration. Raw per-operation CSV files remain local under
`experiments/track_c/raw/<run_id>/`. Reviewed manifests, summaries, tables, and
SHA-256 checksums are versioned under `experiments/track_c/`.

No private key, signature seed, account identifier, session token, OTP, or
reusable credential may be written to an artifact. A clean source tree is
required for a confirmatory run.

## Interpretation Limits

C1 supports claims about implementation-level software costs and verifier
scalability on the measured host. It does not support claims about network
latency, browser ceremony time, secure hardware, mobile interaction, user
decision time, Redis/Postgres behavior, multi-host scaling, or failure
recovery. Those require the separately identified evidence classes above.
