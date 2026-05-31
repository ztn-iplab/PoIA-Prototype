# OAuth/API Integration with PoIA

| Mode | Scenario | Accepted | Correct Decision Rate | Tampering Rejection Rate | Median Verification Overhead (ms) | Reasons |
|---|---|---:|---:|---:|---:|---|
| oauth_only | api_tampering_wrong_key | 60/60 | 100.0% | 0.0% | 0.0057 | oauth_scope_authorized |
| oauth_only | api_tampering_wrong_project | 60/60 | 100.0% | 0.0% | 0.0057 | oauth_scope_authorized |
| oauth_only | cross_action_token_misuse | 60/60 | 100.0% | 0.0% | 0.0057 | oauth_scope_authorized |
| oauth_only | legitimate_api_call | 60/60 | 100.0% | 0.0% | 0.0060 | oauth_scope_authorized |
| oauth_plus_poia | api_tampering_wrong_key | 0/60 | 100.0% | 100.0% | 0.0220 | intent_mismatch |
| oauth_plus_poia | api_tampering_wrong_project | 0/60 | 100.0% | 100.0% | 0.0220 | intent_mismatch |
| oauth_plus_poia | cross_action_token_misuse | 0/60 | 100.0% | 100.0% | 0.0220 | intent_mismatch |
| oauth_plus_poia | legitimate_api_call | 60/60 | 100.0% | 0.0% | 0.0221 | oauth_and_poia_authorized |
