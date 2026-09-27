# Track C1 Protocol Performance Results

> **Note on paths in this directory.** Documents here describe the experiment
> designs and the runs recorded at the time of writing. Result packages named
> after superseded runs were removed in the 2026-09-10 evidence reset and are
> not in this repository; `REPRODUCTION.md` lists the packages the manuscript
> actually reports and the runner that regenerates each one.

Run ID: `track-c-confirmatory-01`

Frozen commit: `e7440e683d63ef01e37a8967325ecd327aca35ae`

The fixed run contains 15,000 measured component operations after 1,500 total
warm-ups and 325,000 concurrent verifier decisions across 75 cells. All
325,000 decisions matched their generated references: zero incorrect accepts,
zero incorrect rejects, and no missing tasks. The checksum inventory verified
all reviewed and raw artifacts.

## Component Cost

| Software path | n | Median total (ms) | IQR (ms) | P95 (ms) | P99 (ms) |
|---|---:|---:|---:|---:|---:|
| Session baseline | 5,000 | 0.0335 | 0.0017 | 0.0424 | 0.1269 |
| PoIA WebAuthn-shaped P-256 | 5,000 | 0.1373 | 0.0047 | 0.1550 | 0.2534 |
| PoIA ZT-shaped P-256 | 5,000 | 0.1371 | 0.0027 | 0.1499 | 0.1688 |

For both PoIA paths, P-256 verification was the largest measured component
(0.0643 ms median), followed by signature generation (0.0285-0.0286 ms), proof
construction (0.0168-0.0169 ms), semantic comparison (0.0113-0.0114 ms), and
canonicalization (0.0104 ms). Locked in-memory nonce consumption was 0.0006 ms
median. Audit JSON serialization was 0.0028 ms median; this excludes durable
log I/O.

## Throughput and Nonce Storage

The in-memory PoIA verifier sustained approximately 10,657-13,098 decisions/s
for all-accept cells across concurrency 1-200. P95 decision latency remained
0.073-0.086 ms, below the pre-registered 20 ms local threshold. The
pre-registered saturation rule identifies concurrency 10 because throughput
did not rise by 5% and P95 increased relative to concurrency 1; later
fluctuations did not establish sustained scaling on this single Python process.

SQLite materially changed concurrent acceptance behavior because each accepted
proof performs an atomic write transaction. For the WebAuthn-shaped path,
all-accept throughput declined from 9,279 decisions/s at concurrency 1 to 3,368
at concurrency 200, while P95 rose from 0.113 ms to 148.427 ms and first crossed
20 ms at concurrency 100. For the ZT-shaped path, throughput declined from
9,527 to 3,921 decisions/s and P95 rose from 0.111 ms to 119.812 ms, first
crossing 20 ms at concurrency 200. All-reject semantic-mismatch cells avoided
nonce writes and retained roughly 11,148-13,194 decisions/s with P95 at or below
0.077 ms across both proof shapes.

The result therefore attributes high-concurrency tail latency to serialization
in the local durable nonce store, not to canonicalization or P-256 verification.
It motivates a separately measured production nonce-store design rather than a
claim that SQLite represents Redis or PostgreSQL behavior.

## Limits

These are local software measurements. They exclude browser ceremonies,
platform authenticators, handset secure hardware, TLS/network delay, user
review, physical interaction, database audit writes, and multi-host deployment.
The 200 genuine WebAuthn and 200 genuine ZT-Authenticator sessions remain the
only evidence class for end-to-end authenticator latency. Track C2 remains
required for distributed placement and fault injection.

Reviewed artifacts are under `experiments/track_c/`. The 20 MB raw archive is
local under `experiments/track_c/raw/track-c-confirmatory-01/` and is frozen by
`experiments/track_c/analysis/track-c-confirmatory-01-checksums.sha256`.
