# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 16622.8 | 0.0010 | 0.0073 | 0.0000 | 0.0091 | 0.0189 | 0.0189 | 0.0239 |
| PoIA with WebAuthn | 10 | 4847.4 | 0.0024 | 0.0224 | 0.2166 | 0.2767 | 0.5354 | 5500.5354 | 5501.2912 |
| PoIA with ZT-Authenticator | 10 | 5050.8 | 0.0024 | 0.0222 | 0.3725 | 0.1387 | 0.6710 | 3400.6710 | 3402.9218 |
