# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 20320.1 | 0.0003 | 0.0040 | 0.0000 | 0.0059 | 0.0112 | 0.0112 | 0.0239 |
| PoIA with WebAuthn | 120 | 4931.5 | 0.0024 | 0.0229 | 0.2191 | 0.3133 | 0.5563 | 5500.5563 | 5510.4101 |
| PoIA with ZT-Authenticator | 120 | 4729.7 | 0.0025 | 0.0231 | 0.2849 | 0.2406 | 0.6068 | 3400.6068 | 3416.7861 |
