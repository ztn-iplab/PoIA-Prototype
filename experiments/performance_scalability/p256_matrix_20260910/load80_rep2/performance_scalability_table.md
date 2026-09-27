# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 80 | 35320.7 | 0.0003 | 0.0039 | 0.0000 | 0.0058 | 0.0108 | 0.0108 | 0.0150 |
| PoIA with WebAuthn | 80 | 5476.1 | 0.0020 | 0.0218 | 1.4294 | 0.1460 | 1.7845 | 5501.7845 | 5509.0763 |
| PoIA with ZT-Authenticator | 80 | 6065.0 | 0.0018 | 0.0185 | 4.2883 | 0.1349 | 4.8744 | 3404.8744 | 3419.6444 |
