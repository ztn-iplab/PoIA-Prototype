# OAuth/API Integration: `oauth-v2-20260910`

| Mode | Scenario | Accepted | State transitions | Correct | False accept | False reject | Median ms | P95 ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| oauth_only | exact_request | 200/200 | 200 | 200/200 | 0 | 0 | 6.3394 | 8.9442 |
| oauth_only | cross_action_substitution | 200/200 | 200 | 200/200 | 0 | 0 | 6.3319 | 8.2923 |
| oauth_only | target_object_substitution | 200/200 | 200 | 200/200 | 0 | 0 | 8.0542 | 16.2811 |
| oauth_only | scope_parameter_substitution | 200/200 | 200 | 200/200 | 0 | 0 | 7.8025 | 9.6277 |
| oauth_plus_poia | exact_request | 200/200 | 200 | 200/200 | 0 | 0 | 8.0048 | 9.6902 |
| oauth_plus_poia | cross_action_substitution | 0/200 | 0 | 200/200 | 0 | 0 | 2.2707 | 2.7076 |
| oauth_plus_poia | target_object_substitution | 0/200 | 0 | 200/200 | 0 | 0 | 2.5291 | 2.8854 |
| oauth_plus_poia | scope_parameter_substitution | 0/200 | 0 | 200/200 | 0 | 0 | 2.3303 | 2.7342 |
