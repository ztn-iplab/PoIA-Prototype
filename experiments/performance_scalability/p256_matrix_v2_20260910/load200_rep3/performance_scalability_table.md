# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 200 | 25358.3 | 0.0003 | 0.0039 | 0.0000 | 0.0058 | 0.0108 | 0.0108 | 0.0224 |
| PoIA with WebAuthn | 200 | 5354.7 | 0.0023 | 0.0229 | 0.3271 | 0.3116 | 0.6989 | 5500.6989 | 5520.4040 |
| PoIA with ZT-Authenticator | 200 | 5172.6 | 0.0025 | 0.0229 | 0.2646 | 0.1454 | 0.5493 | 3400.5493 | 3409.3963 |
