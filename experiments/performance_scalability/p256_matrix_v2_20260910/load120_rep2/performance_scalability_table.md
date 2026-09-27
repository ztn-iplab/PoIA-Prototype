# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 120 | 19329.6 | 0.0004 | 0.0044 | 0.0000 | 0.0060 | 0.0122 | 0.0122 | 0.0238 |
| PoIA with WebAuthn | 120 | 5286.1 | 0.0024 | 0.0225 | 0.3062 | 0.3127 | 0.6826 | 5500.6826 | 5528.9898 |
| PoIA with ZT-Authenticator | 120 | 4342.0 | 0.0026 | 0.0232 | 0.2959 | 0.1783 | 0.5999 | 3400.5999 | 3415.0995 |
