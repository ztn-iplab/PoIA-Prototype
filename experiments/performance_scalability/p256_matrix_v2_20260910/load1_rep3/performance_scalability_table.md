# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 19447.2 | 0.0004 | 0.0041 | 0.0000 | 0.0058 | 0.0112 | 0.0112 | 0.0290 |
| PoIA with WebAuthn | 1 | 3492.0 | 0.0015 | 0.0198 | 0.0814 | 0.1280 | 0.2342 | 5500.2342 | 5500.3552 |
| PoIA with ZT-Authenticator | 1 | 3629.1 | 0.0014 | 0.0177 | 0.0686 | 0.1135 | 0.2058 | 3400.2058 | 3400.3182 |
