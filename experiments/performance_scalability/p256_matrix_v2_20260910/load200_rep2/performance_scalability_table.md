# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 200 | 30500.0 | 0.0003 | 0.0039 | 0.0000 | 0.0059 | 0.0110 | 0.0110 | 0.0205 |
| PoIA with WebAuthn | 200 | 5360.6 | 0.0024 | 0.0230 | 0.3597 | 0.3113 | 0.7411 | 5500.7411 | 5520.2906 |
| PoIA with ZT-Authenticator | 200 | 5183.7 | 0.0025 | 0.0232 | 0.2802 | 0.1456 | 0.5640 | 3400.5640 | 3410.3039 |
