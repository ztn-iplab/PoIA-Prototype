# Track C2 Distributed Enforcement Results

> **Note on paths in this directory.** Documents here describe the experiment
> designs and the runs recorded at the time of writing. Result packages named
> after superseded runs were removed in the 2026-09-10 evidence reset and are
> not in this repository; `REPRODUCTION.md` lists the packages the manuscript
> actually reports and the runner that regenerates each one.

Run ID: `track-c2-confirmatory-01`

Frozen commit: `2b9749fbe23a8459758e5e459b619b57af915084`

The run contains 16,000 healthy loopback HTTP decisions: 2,000 legitimate and
2,000 semantic-mismatch requests under each of four enforcement placements.
All decisions matched their references, with zero incorrect accepts, zero
incorrect rejects, and no missing rows.

| Topology | Legitimate median (ms) | Legitimate P95 (ms) | Mismatch median (ms) | Mismatch P95 (ms) |
|---|---:|---:|---:|---:|
| Gateway-only | 0.4261 | 0.5205 | 0.1017 | 0.1136 |
| Service-local | 0.5682 | 0.6258 | 0.5674 | 0.6182 |
| Shared verifier | 1.0576 | 1.2248 | 1.0525 | 1.3168 |
| Hybrid gateway + shared verifier | 1.2186 | 1.5194 | 0.1618 | 0.1744 |

Relative to gateway-only legitimate execution, median added loopback latency
was 0.1421 ms for service-local verification, 0.6315 ms for the shared verifier,
and 0.7925 ms for hybrid double enforcement. Gateway-only and hybrid rejected
semantic mismatches before forwarding, which explains their shorter mismatch
latency. All healthy P95 values remained below the pre-registered 20 ms local
threshold.

The independent verifier process was then terminated for the shared and hybrid
topologies. All 400 legitimate outage requests failed closed and none executed.
P95 detection latency was 0.7398 ms for shared-verifier placement and 1.0320 ms
for hybrid placement. Restart-to-successful-probe recovery was 435.7548 ms and
536.0378 ms, respectively; each topology then accepted all 200 confirmation
requests.

The result demonstrates fail-closed behavior for a complete verifier-process
outage on loopback. It does not establish behavior under partitions, slow or
Byzantine verifiers, split-brain nonce state, TLS failure, replicated stores, or
production orchestration. Gateway-only and service-local were unaffected
because they do not depend on the shared process; this is dependency avoidance,
not evidence of verifier replication.

Reviewed artifacts are under `experiments/track_c/`. Raw rows remain local at
`experiments/track_c/raw/track-c2-confirmatory-01/` and are frozen by the run's
checksum inventory.
