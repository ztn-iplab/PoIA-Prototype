# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 24441.4 | 0.0003 | 0.0040 | 0.0000 | 0.0059 | 0.0110 | 0.0110 | 0.0222 |
| PoIA with WebAuthn | 1 | 4080.0 | 0.0014 | 0.0173 | 0.0735 | 0.1131 | 0.2092 | 5500.2092 | 5500.2515 |
| PoIA with ZT-Authenticator | 1 | 4130.7 | 0.0013 | 0.0173 | 0.0690 | 0.1128 | 0.2044 | 3400.2044 | 3400.2457 |
