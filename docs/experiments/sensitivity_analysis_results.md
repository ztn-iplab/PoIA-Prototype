# Experiment 10: Sensitivity Analysis Results

Run: `sensitivity-confirmatory-01`

## Method

The pre-registered local microbenchmark separated expiry policy, intent
complexity, and concurrency. The expiry matrix evaluated 30, 60, and 120 second
windows at 11 modeled arrival delays. The compute matrix performed 200 P-256
operations in each of eight parameter-count and structure cells. The
concurrency matrix performed 500 operations at each of 1, 10, 50, and 100
workers. Production canonical JSON encoding was used throughout.

## Expiry Policy

All three exact-boundary cases were accepted. All 15 post-window cases were
rejected, and there were zero false rejections. The configured 30, 60, and 120
second windows are upper bounds on replay exposure, not observed replay-success
durations; one-time nonce consumption remains required within each window.

## Intent Complexity

| Parameters | Shape | Bytes | Canonicalize median/P95 (us) | Sign median/P95 (us) | Verify median/P95 (us) | Operation median/P95 (us) |
|---:|---|---:|---:|---:|---:|---:|
| 5 | flat | 328 | 13.98/33.42 | 29.08/43.75 | 65.38/106.33 | 109.17/213.88 |
| 5 | nested | 404 | 24.79/67.33 | 30.56/107.12 | 68.00/204.00 | 123.79/316.67 |
| 20 | flat | 688 | 18.79/22.17 | 29.88/33.71 | 67.67/73.75 | 116.75/131.17 |
| 20 | nested | 764 | 30.10/37.92 | 29.65/35.33 | 65.83/77.04 | 127.85/149.92 |
| 50 | flat | 1,408 | 29.77/32.92 | 29.21/34.75 | 64.88/74.25 | 124.79/140.04 |
| 50 | nested | 1,484 | 40.71/45.46 | 28.92/33.25 | 64.71/74.42 | 134.71/152.33 |
| 100 | flat | 2,608 | 48.12/56.71 | 29.50/36.29 | 65.08/70.04 | 142.96/161.42 |
| 100 | nested | 2,684 | 58.88/68.58 | 29.33/32.08 | 65.12/72.67 | 153.94/171.08 |

Canonicalization increased with parameter count and nested structure. Median
P-256 signing and verification remained approximately 29--31 us and 65--68 us,
respectively. No signature verification failed.

## Concurrency

Throughput ranged from 6,210 to 7,363 operations/s across 1--100 local worker
threads. Median operation latency ranged from 122.38 to 129.21 us, and no
verification failed. This short in-memory test is evidence of local compute
stability, not distributed service capacity or physical-authenticator latency.

## Reproduction

```sh
PYTHONPYCACHEPREFIX=/tmp/poia-pycache \
  /private/tmp/poia-track-a-venv/bin/python \
  scripts/run_sensitivity_analysis.py \
  --run-id sensitivity-confirmatory-01
```

The manifest records source hashes, runtime versions, algorithm, platform, and
fixed configuration. Raw expiry, compute, and concurrency rows, summaries,
tables, and SHA-256 checksums are under `experiments/sensitivity_analysis/`.
