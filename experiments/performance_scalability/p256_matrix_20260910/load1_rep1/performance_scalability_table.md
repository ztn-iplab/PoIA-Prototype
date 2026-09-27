# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 29564.9 | 0.0003 | 0.0040 | 0.0000 | 0.0060 | 0.0112 | 0.0112 | 0.0208 |
| PoIA with WebAuthn | 1 | 4325.9 | 0.0013 | 0.0174 | 0.0719 | 0.1131 | 0.2062 | 5500.2063 | 5500.2216 |
| PoIA with ZT-Authenticator | 1 | 4470.7 | 0.0013 | 0.0175 | 0.0664 | 0.1133 | 0.2007 | 3400.2007 | 3400.2363 |
