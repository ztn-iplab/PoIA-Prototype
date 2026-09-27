# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 21197.4 | 0.0003 | 0.0040 | 0.0000 | 0.0057 | 0.0108 | 0.0108 | 0.0226 |
| PoIA with WebAuthn | 80 | 4857.2 | 0.0024 | 0.0228 | 0.1867 | 0.3081 | 0.4630 | 5500.4630 | 5502.7208 |
| PoIA with ZT-Authenticator | 80 | 5191.1 | 0.0025 | 0.0226 | 0.2762 | 0.1358 | 0.4946 | 3400.4946 | 3414.0906 |
