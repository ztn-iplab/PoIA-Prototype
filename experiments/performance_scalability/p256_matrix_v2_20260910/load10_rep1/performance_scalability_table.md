# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 10 | 10108.0 | 0.0010 | 0.0081 | 0.0000 | 0.0095 | 0.0203 | 0.0203 | 0.0524 |
| PoIA with WebAuthn | 10 | 4944.3 | 0.0024 | 0.0224 | 0.2446 | 0.2766 | 0.5721 | 5500.5721 | 5501.7403 |
| PoIA with ZT-Authenticator | 10 | 4802.0 | 0.0025 | 0.0224 | 0.2199 | 0.1427 | 0.4310 | 3400.4310 | 3400.8863 |
