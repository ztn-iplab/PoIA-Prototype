# PoIA Experiment Designs

This document explains what each experiment is testing, how it is implemented,
what artifacts it produces, and how to interpret the results.

## Experiment 1: Security Effectiveness Expansion

**Question:** Does PoIA block broader session-abuse patterns that baseline
session authorization accepts?

**Implementation:** `scripts/run_security_effectiveness_expanded.py`

The script runs ten attack scenarios under two modes:

- `baseline`: a valid session is enough to execute the attempted action.
- `poia`: the verifier requires a matching intent proof.

Scenarios include replay, relay phishing, session misuse, intent substitution,
scope tampering, context substitution, expired proof reuse, concurrent-session
misuse, multi-step workflow abuse, and confused-deputy API calls.

**Metrics:** attack success rate, correct rejection rate, incorrect acceptance
rate, and denial reason.

**Artifacts:** `experiments/security_effectiveness_expanded/`

**Interpretation:** The expected pattern is that baseline accepts session-abuse
attempts while PoIA rejects them with specific reasons such as `nonce_reuse`,
`semantic_mismatch`, `context_mismatch`, `expired`, or `missing_proof`.

## Experiment 2: Functional Correctness Stress Test

**Question:** Does PoIA accept exact intent matches and reject non-matching
intent variants?

**Implementation:** `scripts/measure_functional_correctness.py`

The experiment mutates one intent dimension at a time:

- action
- amount/value
- target object
- user identity
- relying-party context
- nonce
- timestamp
- validity window
- canonicalization order
- encoding variations

Canonicalization-order and encoding cases are expected to remain acceptable when
the semantic intent is unchanged. Semantic mutations are expected to be rejected.

**Metrics:** correct acceptances, correct rejections, false acceptances, and
false rejections.

**Artifacts:** `experiments/functional_correctness_stress/`

**Interpretation:** False acceptances would weaken Intent Integrity. False
rejections would indicate usability or interoperability risk.

## Experiment 3: Performance and Scalability

**Question:** What is the operational cost of PoIA and how does it behave under
increased load?

**Implementation:** `scripts/measure_performance_scalability.py`

The script compares:

- baseline session authorization
- PoIA with WebAuthn
- PoIA with ZT-Authenticator

It measures intent construction, canonicalization, signing, verification,
server-side latency, end-to-end latency, and throughput. User interaction delay
is modeled separately so reviewers can distinguish cryptographic cost from human
approval cost.

**Loads:** 1, 10, 50, 100, and 200 users by default.

**Artifacts:** `experiments/performance_scalability/`

**Interpretation:** Server-side proof overhead should stay small and predictable.
End-to-end latency is dominated by the modeled user approval step for WebAuthn
and ZT-Authenticator modes.

## Experiment 4: Signing Backend Comparison

**Question:** Is PoIA tied to a single signing implementation?

**Implementation:** `scripts/compare_signing_backends.py`

The script compares:

- WebAuthn platform authenticator
- ZT-Authenticator
- software signing baseline
- hardware-backed key, if locally configured

Each backend is evaluated through the same PoIA verifier shape: construct
intent, canonicalize, sign, verify, and record latency/failure behavior.

**Metrics:** latency, failure rate, deployment complexity, security assumptions,
and user interaction cost.

**Artifacts:** `experiments/signing_backend_comparison/`

**Interpretation:** The paper claim is not that all backends are equally secure.
The claim is that PoIA is a model that can be instantiated by different signing
backends with different deployment/security tradeoffs.

## Experiment 5: Auditability

**Question:** Does PoIA improve forensic reconstruction compared with baseline
authorization logs?

**Implementation:** `scripts/run_auditability_experiment.py`

The script generates baseline and PoIA logs, then runs an auditor reconstruction
pass over each event.

The auditor tries to reconstruct:

- who authorized
- what action
- what object/scope
- when
- under which context
- with which proof
- why rejected or executed

**Metrics:** reconstruction completeness, ambiguity rate, missing evidence rate,
and reconstruction time.

**Artifacts:** `experiments/auditability/`

**Interpretation:** PoIA logs should be more complete because proof id, intent
hash, context, scope, and decision reason are explicit authorization evidence.

## Experiment 6: Cross-Domain Generality

**Question:** Does the same PoIA verifier work beyond banking?

**Implementation:** `scripts/run_cross_domain_generality.py`

The verifier is reused while the intent schema changes across domains:

- banking transfer
- enterprise admin role grant
- healthcare record export
- cloud/API key rotation

Each domain includes exact-match cases and tampering cases.

**Metrics:** correct acceptances, correct rejections, false acceptances, false
rejections, and verification latency.

**Artifacts:** `experiments/cross_domain_generality/`

**Interpretation:** If the same verifier accepts exact matches and rejects
schema-specific tampering across domains, it supports the claim that PoIA is a
general authorization model rather than a banking-only feature.

## Experiment 7: OAuth/API Integration

**Question:** Can PoIA complement OAuth by blocking misuse of a valid token for
the wrong high-risk action or object?

**Implementation:** `scripts/run_oauth_api_integration.py`

This experiment is documented in detail in
`docs/experiments/oauth_api_integration.md`.

The short version:

- OAuth-only checks token validity and scope.
- OAuth + PoIA checks token validity, scope, proof validity, and exact intent
  equality.

**Metrics:** cross-action token misuse success, API tampering rejection, correct
decision rate, and proof verification overhead.

**Artifacts:** `experiments/oauth_api_integration/`

**Interpretation:** OAuth-only accepts requests when the bearer token has a broad
enough scope. OAuth + PoIA rejects requests whose action/object/context differs
from the approved intent.

## Experiment 8: Formal Verification Expansion

**Question:** Can the core PoIA security properties be stated and proved in a
symbolic model?

**Implementation:**

- `tamarin/poia_protocol.spthy`
- `scripts/generate_formal_verification_artifacts.py`
- `scripts/run_tamarin_poia.sh`

This experiment is documented in detail in
`docs/experiments/tamarin_formal_verification.md`.

**Verified properties:**

- no execution without matching intent
- nonce freshness
- replay resistance
- intent non-transferability
- context confinement
- session compromise does not imply execution
- action substitution impossibility

**Artifacts:** `experiments/formal_verification_expansion/` and
`tamarin/results/`

**Interpretation:** Tamarin proves the abstract authorization relation. It does
not prove every implementation detail of the prototype, but it strengthens the
theoretical contribution.

## Experiment 9: Usability-Light Structured Analysis

**Question:** Are intent statements understandable enough for a modest reviewer
concern analysis without turning the paper into an HCI study?

**Implementation:** `scripts/run_usability_structured_analysis.py`

The script evaluates structured intent statements across the same representative
domains used in the cross-domain experiment.

It checks whether required terms are present and whether changed fields are
visible in the human-readable statement.

**Metrics:** understandable score, changed-field detectability, estimated
approval/rejection time, confusion rate, and habituation risk.

**Artifacts:** `experiments/usability_structured/`

**Interpretation:** This is a structured heuristic analysis, not a participant
study. If later replaced with a 10-20 participant study, the same fields can be
used as study tasks.

## Experiment 10: Sensitivity Analysis

**Question:** How stable is PoIA under different validity windows, delays,
concurrency, intent sizes, and canonicalization complexity?

**Implementation:** `scripts/run_sensitivity_analysis.py`

The script varies:

- nonce validity window: 30, 60, 120 seconds
- network delay
- concurrent requests
- intent size
- number of parameters
- canonicalization complexity

**Metrics:** latency, false rejection, replay window exposure, and verification
cost.

**Artifacts:** `experiments/sensitivity_analysis/`

**Interpretation:** Expected false rejections occur when simulated delay exceeds
the validity window. Replay exposure grows with TTL. Verification cost should
remain bounded by intent size and canonicalization complexity.
