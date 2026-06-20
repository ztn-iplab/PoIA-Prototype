# Track A Functional Correctness: Verifier-Only Results

These results exercise production canonicalization and authorization-state logic without claiming a real signing backend.

| Scenario | Expected | n | Correct (95% Wilson CI) | False accept | False reject |
|---|---:|---:|---:|---:|---:|
| exact_legitimate_match | accept | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| action_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| amount_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| currency_partial_field_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| target_object_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| principal_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| rp_context_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| nonce_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| nonce_reuse | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| expired_intent | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| validity_boundary_59_9 | accept | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| validity_boundary_60_1 | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| validity_constraint_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| canonical_field_order | accept | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| unicode_and_numeric_encoding | accept | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
| workflow_identifier_mismatch | reject | 200 | 200/200 (100.00%, 98.12-100.00%) | 0 | 0 |
