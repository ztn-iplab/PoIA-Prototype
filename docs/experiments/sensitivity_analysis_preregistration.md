# Experiment 10 Pre-registration: Sensitivity Analysis

Pre-registration date: 2026-06-21 (Asia/Tokyo)

## Research Questions

1. How do 30, 60, and 120 second proof-validity windows behave under fixed
   arrival delays around each expiry boundary?
2. How do canonicalization and P-256 signing and verification costs change with
   intent size, parameter count, and flat versus nested structure?
3. How does the same in-memory operation behave at 1, 10, 50, and 100 worker
   concurrency?

## Fixed Design

The expiry-policy matrix uses validity windows of 30, 60, and 120 seconds and
modeled arrival delays of 0, 29, 30, 31, 59, 60, 61, 119, 120, 121, and 150
seconds. A proof is valid at the exact boundary and expires only when delay is
greater than its configured window. These delays are deterministic arrival-time
injections; the experiment does not sleep or claim measured network latency.

The compute matrix uses 5, 20, 50, and 100 scope parameters in flat and nested
structures, with 200 operations per cell. It uses the production
`app.intent_codec.canonical_json` implementation and P-256 ECDSA with SHA-256.
The concurrency matrix uses a fixed nested 20-parameter intent, 500 operations
per cell, and 1, 10, 50, and 100 worker threads.

## Outcomes

- policy acceptance and rejection at each expiry boundary;
- false rejection, defined only as rejection at or before the validity limit;
- configured replay-exposure upper bound, reported as the validity window;
- canonical intent size in bytes;
- canonicalization, signature generation, and verification latency;
- end-to-end in-memory operation latency; and
- wall-clock throughput under each concurrency level.

Report median and 95th percentile latency. Do not reinterpret expected expiry as
false rejection. One-time nonce consumption remains the replay defense within a
validity window; the window is an exposure upper bound, not a measured replay
success rate.

## Artifact and Interpretation Controls

The runner requires a clean tree and an unused run identifier. The manifest
records the repository commit, runner and canonicalizer hashes, Python and
cryptography versions, platform, fixed configuration, and key algorithm. Raw
rows, summaries, tables, and SHA-256 checksums are retained.

This is a controlled local microbenchmark. It does not measure internet delay,
mobile user interaction, hardware authenticator latency, or distributed service
capacity. Those outcomes must remain separate from Track C and the pending 200
real-authenticator operations.
