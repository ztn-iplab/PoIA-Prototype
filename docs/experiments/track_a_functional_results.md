# Track A Functional Correctness Results

Run ID: `functional-verifier-df29fc2-n200`

Evidence class: backend-independent verifier-only measurement. These results do
not claim WebAuthn or ZT-Authenticator interaction or signature verification.

## Frozen Run

- RP/harness commit: `df29fc23efd26ef617167b40c6d70de9740891cd`
- Repository state: clean
- Seed: `20260620`
- Scenarios: 16 declarative cases
- Trials per scenario: 200
- Total decisions: 3,200
- Local raw directory: `experiments/track_a/raw/functional-verifier-df29fc2-n200/`

## Findings

- Correct decisions: 3,200/3,200, 100% (Wilson 95% CI 99.88-100%).
- False acceptances: 0/2,400 expected rejections, 0% (Wilson 95% CI 0-0.16%).
- False rejections: 0/800 expected acceptances, 0% (Wilson 95% CI 0-0.48%).
- Every scenario contains exactly 200 observations.
- The run retained all decisions; no exclusions or early stopping occurred.

Expected acceptances covered exact matches, submission at T+59.9 seconds,
canonical field-order variation, and NFC/NFD plus integer-equivalent numeric
encoding. Expected rejections covered action, amount, currency, target,
principal, RP, nonce, replay, expiration, T+60.1 seconds, validity constraints,
and workflow substitutions.

## Interpretation Boundary

The findings support deterministic canonicalization, exact semantic matching,
freshness comparison, and one-time proof-state behavior in the production
verifier implementation. They do not measure authenticator usability,
signature-generation failures, browser interoperability, network behavior, or
real WebAuthn/ZT signing latency. Those cells remain pending for the separate
200-action backend runs.

The versioned manifest, aggregate JSON, manuscript table, and checksums are in
`experiments/track_a/`. Per-trial JSONL and CSV remain local in the raw directory
and can be regenerated with the command documented in the Track A README.
