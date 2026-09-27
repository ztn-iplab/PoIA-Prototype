# Track C2 Pre-registration: Distributed Enforcement and Faults

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Question

How do gateway-only, service-local, shared-authorization-service, and hybrid
PoIA enforcement differ in loopback HTTP latency and behavior when the shared
verifier becomes unavailable?

## Topologies

- `gateway_only`: the gateway verifies the proof and forwards a signed-internal
  decision marker; the resource service does not reverify the proof.
- `service_local`: the gateway forwards the request and the resource service
  verifies the proof locally.
- `shared_verifier`: the resource service calls an independent verifier process
  over HTTP before execution.
- `hybrid`: the gateway verifies first and the resource service independently
  calls the shared verifier before execution.

The experiment uses loopback TCP with separate resource and shared-verifier
processes. It is not a multi-host or wide-area-network result.

## Workload

- 200 warm-up requests per topology.
- 2,000 legitimate and 2,000 semantic-mismatch requests per topology.
- One request at a time to isolate topology/hop cost from Track C1 concurrency.
- P-256 proofs are generated before timing. Each request carries a unique
  nonce; private keys remain only in the controller process.
- The same canonical intent, proof format, and decision predicate are used in
  all topologies.

## Fault Injection

After normal trials, the shared-verifier process is terminated. For
`shared_verifier` and `hybrid`, 200 legitimate requests are issued during the
outage. The required behavior is fail-closed: HTTP 503 or an explicit denial,
with zero executions. Detection latency is request start to failure response.

The verifier process is then restarted. Recovery time is measured from restart
initiation until a legitimate probe is accepted. A final set of 200 legitimate
requests per dependent topology confirms recovered execution.

Gateway-only and service-local are documented as not dependent on the shared
verifier; they are not counted as fault-tolerant replicas.

## Metrics

For normal trials report n, median, IQR, P95, and P99 end-to-end loopback
latency, correct accepts, correct rejects, incorrect accepts, and incorrect
rejects. For outage trials report failed-closed count, incorrect executions,
detection-latency distribution, and recovery time.

The local operational threshold is P95 below 20 ms in healthy operation. This
is an engineering threshold for the measured host, not a production SLA.

## Artifacts and Validity

The confirmatory run requires a clean tree and fixed manifest. Raw request rows
are local under `experiments/track_c/raw/<run-id>/`; reviewed manifests,
summaries, tables, and checksums are versioned. No private key, token, OTP,
account data, or reusable credential may be recorded.

The runner is invalid if any normal decision differs from its reference, an
outage request executes in a dependent topology, a process fails to restart,
or the expected number of rows is not recorded. Results support only local
deployment-structure and fail-closed claims; they do not characterize network
partitions, split brain, replicated nonce stores, TLS termination, or
production orchestration.
