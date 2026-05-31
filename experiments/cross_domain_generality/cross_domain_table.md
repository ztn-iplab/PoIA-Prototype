# PoIA Cross-Domain Generality

| Domain | Scope Fields | Cases | Correct Acceptances | Correct Rejections | False Acceptances | False Rejections | Median Verify (ms) |
|---|---|---|---:|---:|---:|---:|---:|
| banking transfer | amount, currency, from_account, to_account | amount_tamper, exact_match, recipient_tamper | 60 | 120 | 0 | 0 | 0.0165 |
| enterprise admin | duration_hours, role, target_user, tenant | exact_match, role_escalation, tenant_tamper | 60 | 120 | 0 | 0 | 0.0161 |
| healthcare export | patient_id, purpose, recipient, record_type | exact_match, patient_tamper, purpose_tamper | 60 | 120 | 0 | 0 | 0.0161 |
| cloud api | key_id, project, region | exact_match, key_tamper, project_tamper | 60 | 120 | 0 | 0 | 0.0155 |
