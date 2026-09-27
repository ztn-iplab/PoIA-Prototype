# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 33218.2 | 0.0003 | 0.0040 | 0.0000 | 0.0060 | 0.0111 | 0.0111 | 0.0166 |
| PoIA with WebAuthn | 120 | 5766.2 | 0.0018 | 0.0182 | 2.5616 | 0.1340 | 3.3261 | 5503.3261 | 5512.4612 |
| PoIA with ZT-Authenticator | 120 | 5949.7 | 0.0018 | 0.0183 | 3.2566 | 0.1344 | 3.7836 | 3403.7836 | 3414.1614 |
