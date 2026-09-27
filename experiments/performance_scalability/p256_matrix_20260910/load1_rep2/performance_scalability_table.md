# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 38000.6 | 0.0003 | 0.0040 | 0.0000 | 0.0058 | 0.0110 | 0.0110 | 0.0137 |
| PoIA with WebAuthn | 1 | 4320.3 | 0.0013 | 0.0174 | 0.0718 | 0.1128 | 0.2059 | 5500.2059 | 5500.2235 |
| PoIA with ZT-Authenticator | 1 | 4183.4 | 0.0014 | 0.0177 | 0.0699 | 0.1140 | 0.2079 | 3400.2079 | 3400.2538 |
