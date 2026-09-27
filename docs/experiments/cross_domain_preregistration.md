# Experiment 6 Pre-registration: Cross-Domain Generality

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Claim Under Test

The same PoIA verification algorithm accepts exact intents and rejects semantic
substitutions across banking, enterprise administration, healthcare, and cloud
API operations. Only the intent schema and values may change between domains.

## Domains and Actions

- Banking: transfer funds.
- Enterprise administration: grant a role.
- Healthcare: export a patient record.
- Cloud/API: rotate a managed key.

Each schema includes an action, domain scope, principal and relying-party
context, workflow or authorization reference, fresh nonce, and validity
constraint.

## Fixed Cases and Sample Size

For each domain, run 200 fresh trials of:

1. exact match (expected accept);
2. action substitution;
3. primary target-object substitution;
4. value or privilege substitution;
5. principal substitution;
6. relying-party substitution;
7. nonce substitution.

Total fixed decisions: 4 domains x 7 cases x 200 = 5,600. This yields 800
expected acceptances and 4,800 expected rejections.

## Verifier

All domains use one verifier function, one P-256 public key, the production
`canonical_json` implementation, and `intent_mismatch_reason`. A fresh P-256
signature and nonce are generated for each trial. The verifier first validates
the signature over the approved canonical intent and then compares the approved
and requested semantics. Domain-specific conditionals are permitted only in
schema and mutation construction, not in verification.

## Metrics and Validity

Report correct acceptances, correct rejections, false acceptances, false
rejections, decision reason, and verification latency (median, IQR, P95, P99).
The run is invalid if any case is missing, any expected/observed decision or
reason differs, the tree is dirty, or private signing material enters an
artifact.

The previous 60-trial files in `experiments/cross_domain_generality/` are
exploratory and are not reused as confirmatory evidence.

## Interpretation Limit

This controlled verifier experiment supports schema-level generality, not a
claim that complete production banking, IAM, healthcare, and cloud platforms
were deployed or usability-tested. Domain policy completeness remains the
responsibility of each schema designer.
