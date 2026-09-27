# Experiment 6: Cross-Domain Generality Results

## Confirmatory Run

- Run ID: `cross-domain-confirmatory-01`
- Frozen implementation commit: `7ce16532987d8a5207c5dd94c6d2abaa245b6692`
- Date: 2026-06-20 (Asia/Tokyo)
- Domains: banking, enterprise administration, healthcare, and cloud/API
- Trials: 200 per case, seven cases per domain
- Total decisions: 5,600

The same P-256 verification function, production canonicalizer, and production
semantic mismatch classifier processed every domain. Only schema construction
and the preregistered mutation location varied by domain. The generated private
key remained process-local and was not persisted.

## Results

| Domain | Correct accepts | Correct rejects | False accepts | False rejects | Median verify | P95 verify |
|---|---:|---:|---:|---:|---:|---:|
| Banking | 200/200 | 1,200/1,200 | 0 | 0 | 0.1283 ms | 0.1876 ms |
| Enterprise | 200/200 | 1,200/1,200 | 0 | 0 | 0.1280 ms | 0.1645 ms |
| Healthcare | 200/200 | 1,200/1,200 | 0 | 0 | 0.1281 ms | 0.1649 ms |
| Cloud/API | 200/200 | 1,200/1,200 | 0 | 0 | 0.1279 ms | 0.1589 ms |

Across all domains, all 800 exact intents were accepted and all 4,800 action,
target, value or privilege, principal, relying-party, and nonce substitutions
were rejected with the preregistered reason. There were no false acceptances or
false rejections.

## Interpretation

The result supports schema-level generality: the verifier did not require
domain-specific authorization logic to enforce exact intent matching. It does
not establish that complete production systems were deployed in all four
domains, that each schema captures every real policy requirement, or that the
software-only signing latency represents WebAuthn or ZT-Authenticator user
interaction.

## Reproduction

```bash
python scripts/run_cross_domain_generality.py \
  --run-id cross-domain-confirmatory-reproduction-01
```

Confirmatory runs require a clean working tree and exactly 200 trials per case.
Review `cross-domain-confirmatory-01-manifest.json`, verify the SHA-256 list,
and inspect the 5,600-row CSV before citing the summary table.
