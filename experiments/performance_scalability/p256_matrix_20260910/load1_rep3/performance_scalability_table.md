# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 38709.4 | 0.0003 | 0.0040 | 0.0000 | 0.0061 | 0.0112 | 0.0112 | 0.0132 |
| PoIA with WebAuthn | 1 | 3606.9 | 0.0015 | 0.0192 | 0.0739 | 0.1208 | 0.2163 | 5500.2163 | 5500.3307 |
| PoIA with ZT-Authenticator | 1 | 4017.6 | 0.0015 | 0.0182 | 0.0708 | 0.1170 | 0.2140 | 3400.2140 | 3400.2778 |
