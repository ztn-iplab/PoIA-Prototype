# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 24180.6 | 0.0003 | 0.0039 | 0.0000 | 0.0057 | 0.0108 | 0.0108 | 0.0228 |
| PoIA with WebAuthn | 1 | 4144.1 | 0.0013 | 0.0176 | 0.0731 | 0.1131 | 0.2083 | 5500.2083 | 5500.2457 |
| PoIA with ZT-Authenticator | 1 | 4151.7 | 0.0014 | 0.0177 | 0.0691 | 0.1133 | 0.2053 | 3400.2053 | 3400.2452 |
