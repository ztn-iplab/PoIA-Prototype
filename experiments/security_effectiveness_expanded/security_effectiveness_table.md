# PoIA Security Effectiveness Expansion

| Scenario | Baseline Attack Success | PoIA Attack Success | PoIA Correct Rejection | PoIA Incorrect Acceptance | PoIA Denial Reason |
|---|---:|---:|---:|---:|---|
| Replay attack | 100.0% | 0.0% | 100.0% | 0.0% | nonce_reuse (60) |
| Relay phishing | 100.0% | 0.0% | 100.0% | 0.0% | semantic_mismatch (60) |
| Session misuse | 100.0% | 0.0% | 100.0% | 0.0% | missing_proof (60) |
| Intent substitution | 100.0% | 0.0% | 100.0% | 0.0% | semantic_mismatch (60) |
| Scope tampering | 100.0% | 0.0% | 100.0% | 0.0% | semantic_mismatch (60) |
| Context substitution | 100.0% | 0.0% | 100.0% | 0.0% | context_mismatch (60) |
| Expired proof reuse | 100.0% | 0.0% | 100.0% | 0.0% | expired (60) |
| Concurrent-session misuse | 100.0% | 0.0% | 100.0% | 0.0% | context_mismatch (60) |
| Multi-step workflow abuse | 100.0% | 0.0% | 100.0% | 0.0% | semantic_mismatch (60) |
| Confused-deputy API call | 100.0% | 0.0% | 100.0% | 0.0% | semantic_mismatch (60) |
