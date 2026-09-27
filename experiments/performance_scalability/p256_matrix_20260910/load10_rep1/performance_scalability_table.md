# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 12415.5 | 0.0010 | 0.0076 | 0.0000 | 0.0090 | 0.0191 | 0.0191 | 0.0237 |
| PoIA with WebAuthn | 10 | 3151.0 | 0.0027 | 0.0254 | 0.2434 | 0.3243 | 0.6309 | 5500.6309 | 5501.8615 |
| PoIA with ZT-Authenticator | 10 | 2002.3 | 0.0052 | 0.0448 | 0.3801 | 0.4572 | 0.9768 | 3400.9768 | 3402.5445 |
