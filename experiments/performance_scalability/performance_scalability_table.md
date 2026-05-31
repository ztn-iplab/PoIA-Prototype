# PoIA Performance and Scalability

Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.

| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline session authorization | 1 | 33259.4 | 0.0003 | 0.0031 | 0.0000 | 0.0043 | 0.0082 | 0.0082 | 0.0178 |
| PoIA with WebAuthn | 1 | 23731.8 | 0.0008 | 0.0052 | 0.0103 | 0.0074 | 0.0244 | 5500.0244 | 5500.0325 |
| PoIA with ZT-Authenticator | 1 | 21304.0 | 0.0009 | 0.0054 | 0.0073 | 0.0078 | 0.0222 | 3400.0222 | 3400.0351 |
| Baseline session authorization | 10 | 39952.7 | 0.0003 | 0.0032 | 0.0000 | 0.0044 | 0.0084 | 0.0084 | 0.0101 |
| PoIA with WebAuthn | 10 | 23398.7 | 0.0008 | 0.0054 | 0.0103 | 0.0075 | 0.0246 | 5500.0246 | 5500.0321 |
| PoIA with ZT-Authenticator | 10 | 25290.6 | 0.0008 | 0.0053 | 0.0068 | 0.0074 | 0.0211 | 3400.0211 | 3400.0295 |
| Baseline session authorization | 50 | 47753.0 | 0.0003 | 0.0029 | 0.0000 | 0.0042 | 0.0078 | 0.0078 | 0.0103 |
| PoIA with WebAuthn | 50 | 17650.4 | 0.0008 | 0.0054 | 0.0104 | 0.0075 | 0.0248 | 5500.0248 | 5500.0754 |
| PoIA with ZT-Authenticator | 50 | 20719.7 | 0.0008 | 0.0054 | 0.0069 | 0.0075 | 0.0212 | 3400.0212 | 3400.0647 |
| Baseline session authorization | 100 | 47869.1 | 0.0003 | 0.0029 | 0.0000 | 0.0041 | 0.0077 | 0.0077 | 0.0100 |
| PoIA with WebAuthn | 100 | 22746.3 | 0.0008 | 0.0053 | 0.0103 | 0.0074 | 0.0245 | 5500.0245 | 5500.0385 |
| PoIA with ZT-Authenticator | 100 | 30839.6 | 0.0008 | 0.0051 | 0.0065 | 0.0072 | 0.0200 | 3400.0200 | 3400.0240 |
| Baseline session authorization | 200 | 51446.3 | 0.0003 | 0.0028 | 0.0000 | 0.0040 | 0.0075 | 0.0075 | 0.0086 |
| PoIA with WebAuthn | 200 | 23337.8 | 0.0008 | 0.0053 | 0.0103 | 0.0074 | 0.0244 | 5500.0244 | 5500.0385 |
| PoIA with ZT-Authenticator | 200 | 30306.6 | 0.0008 | 0.0051 | 0.0065 | 0.0072 | 0.0202 | 3400.0202 | 3400.0235 |
