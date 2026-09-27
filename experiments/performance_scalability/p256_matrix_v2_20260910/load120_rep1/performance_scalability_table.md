# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 26661.4 | 0.0003 | 0.0040 | 0.0000 | 0.0058 | 0.0109 | 0.0109 | 0.0212 |
| PoIA with WebAuthn | 120 | 5408.8 | 0.0024 | 0.0225 | 0.2595 | 0.3108 | 0.6077 | 5500.6077 | 5525.6305 |
| PoIA with ZT-Authenticator | 120 | 4386.3 | 0.0026 | 0.0230 | 0.2639 | 0.1511 | 0.5320 | 3400.5320 | 3403.4940 |
