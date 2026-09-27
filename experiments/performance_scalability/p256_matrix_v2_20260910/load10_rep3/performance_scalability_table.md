# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 17780.8 | 0.0004 | 0.0059 | 0.0000 | 0.0070 | 0.0144 | 0.0144 | 0.0259 |
| PoIA with WebAuthn | 10 | 4941.8 | 0.0024 | 0.0221 | 0.2312 | 0.2675 | 0.5575 | 5500.5575 | 5501.7453 |
| PoIA with ZT-Authenticator | 10 | 5107.5 | 0.0024 | 0.0222 | 0.2930 | 0.1344 | 0.5508 | 3400.5508 | 3402.4185 |
