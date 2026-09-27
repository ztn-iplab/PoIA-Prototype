# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 32470.4 | 0.0003 | 0.0040 | 0.0000 | 0.0059 | 0.0110 | 0.0110 | 0.0218 |
| PoIA with WebAuthn | 80 | 5792.6 | 0.0018 | 0.0190 | 4.8897 | 0.1395 | 5.3028 | 5505.3028 | 5520.4192 |
| PoIA with ZT-Authenticator | 80 | 6036.9 | 0.0018 | 0.0183 | 3.4802 | 0.1333 | 4.0727 | 3404.0727 | 3415.9519 |
