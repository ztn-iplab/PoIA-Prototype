# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 38839.6 | 0.0003 | 0.0039 | 0.0000 | 0.0059 | 0.0110 | 0.0110 | 0.0134 |
| PoIA with WebAuthn | 10 | 3565.0 | 0.0021 | 0.0219 | 0.9175 | 0.2139 | 1.6947 | 5501.6947 | 5506.0531 |
| PoIA with ZT-Authenticator | 10 | 3735.8 | 0.0032 | 0.0295 | 0.3047 | 0.2366 | 0.6715 | 3400.6715 | 3401.8343 |
