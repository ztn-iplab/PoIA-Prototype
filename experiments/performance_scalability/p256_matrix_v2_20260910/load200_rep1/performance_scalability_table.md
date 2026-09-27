# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 200 | 21076.2 | 0.0003 | 0.0039 | 0.0000 | 0.0057 | 0.0107 | 0.0107 | 0.0230 |
| PoIA with WebAuthn | 200 | 5415.1 | 0.0021 | 0.0225 | 1.7596 | 0.3092 | 2.2779 | 5502.2779 | 5525.6406 |
| PoIA with ZT-Authenticator | 200 | 5804.7 | 0.0018 | 0.0221 | 6.4106 | 3.9276 | 14.9275 | 3414.9275 | 3471.2063 |
