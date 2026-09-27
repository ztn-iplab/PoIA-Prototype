# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 33837.5 | 0.0003 | 0.0040 | 0.0000 | 0.0060 | 0.0111 | 0.0111 | 0.0164 |
| PoIA with WebAuthn | 120 | 5812.6 | 0.0018 | 0.0182 | 3.0882 | 0.1339 | 3.7240 | 5503.7240 | 5513.3905 |
| PoIA with ZT-Authenticator | 120 | 5948.4 | 0.0018 | 0.0183 | 3.1769 | 0.1342 | 3.8775 | 3403.8775 | 3414.3519 |
