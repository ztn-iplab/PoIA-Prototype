# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 34451.2 | 0.0003 | 0.0039 | 0.0000 | 0.0058 | 0.0109 | 0.0109 | 0.0159 |
| PoIA with WebAuthn | 80 | 5870.5 | 0.0018 | 0.0182 | 3.2742 | 0.1333 | 3.7958 | 5503.7958 | 5514.3077 |
| PoIA with ZT-Authenticator | 80 | 5313.3 | 0.0024 | 0.0224 | 0.3145 | 0.1335 | 0.5492 | 3400.5492 | 3405.4558 |
