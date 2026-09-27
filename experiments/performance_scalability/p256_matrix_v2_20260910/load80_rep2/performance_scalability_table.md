# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 17143.7 | 0.0005 | 0.0061 | 0.0000 | 0.0088 | 0.0166 | 0.0166 | 0.0350 |
| PoIA with WebAuthn | 80 | 5270.5 | 0.0024 | 0.0225 | 0.1523 | 0.3075 | 0.4684 | 5500.4684 | 5515.3303 |
| PoIA with ZT-Authenticator | 80 | 4700.1 | 0.0025 | 0.0227 | 0.2483 | 0.1446 | 0.4763 | 3400.4763 | 3401.4468 |
