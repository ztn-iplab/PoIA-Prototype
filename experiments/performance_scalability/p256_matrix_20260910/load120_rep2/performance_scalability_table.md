# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 34188.9 | 0.0003 | 0.0039 | 0.0000 | 0.0059 | 0.0110 | 0.0110 | 0.0191 |
| PoIA with WebAuthn | 120 | 5853.0 | 0.0018 | 0.0181 | 2.7532 | 0.1333 | 3.2728 | 5503.2728 | 5512.7876 |
| PoIA with ZT-Authenticator | 120 | 5552.8 | 0.0018 | 0.0183 | 2.3185 | 0.1352 | 2.9693 | 3402.9693 | 3410.9800 |
