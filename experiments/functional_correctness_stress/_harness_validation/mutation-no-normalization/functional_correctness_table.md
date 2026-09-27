| Test category | Cases | Expected | Correct | Errors |
|---|---:|---|---:|---:|
| Exact valid match | 200 | Accept | 200 | 0 |
| Canonical equivalent | 400 | Accept | 0 | 400 |
| Action mismatch | 200 | Reject | 200 | 0 |
| Scope mismatch | 200 | Reject | 200 | 0 |
| Context mismatch | 200 | Reject | 200 | 0 |
| Expired intent | 200 | Reject | 200 | 0 |
| Nonce reuse | 200 | Reject | 200 | 0 |
| Malformed serialization | 200 | Reject | 200 | 0 |

FRR: 66.6667%  FAR: 0.0%
