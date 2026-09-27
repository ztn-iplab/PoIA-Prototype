# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 17581.7 | 0.0010 | 0.0075 | 0.0000 | 0.0089 | 0.0188 | 0.0188 | 0.0238 |
| PoIA with WebAuthn | 10 | 2989.1 | 0.0027 | 0.0261 | 0.2573 | 0.3254 | 0.6837 | 5500.6838 | 5504.8551 |
| PoIA with ZT-Authenticator | 10 | 2942.4 | 0.0035 | 0.0356 | 1.6124 | 1.0075 | 2.9519 | 3402.9519 | 3407.1295 |
