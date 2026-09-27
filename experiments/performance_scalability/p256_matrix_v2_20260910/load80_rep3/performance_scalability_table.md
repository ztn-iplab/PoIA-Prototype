# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 26926.3 | 0.0003 | 0.0040 | 0.0000 | 0.0060 | 0.0112 | 0.0112 | 0.0213 |
| PoIA with WebAuthn | 80 | 4955.5 | 0.0024 | 0.0230 | 0.1012 | 0.3134 | 0.4732 | 5500.4732 | 5503.6762 |
| PoIA with ZT-Authenticator | 80 | 5037.1 | 0.0025 | 0.0228 | 0.2632 | 0.1451 | 0.5178 | 3400.5178 | 3410.3396 |
