# Atomic referent binding: verified

## Current result, 2026-09-08

The primary theory `atomic_referent_binding.spthy` verifies all four original obligations: executable authorization, single execution, causal authorization, and rejection of execution after the committed version has been retired. All six supporting lemmas also verify. Tamarin 1.12.0 / Maude 3.5.1 passed strict well-formedness checks.

The initial successful search used depth bound 10. Every branch closed; this bound limits search, not protocol traces or attacker actions. The completed certificate was subsequently replayed without a search-depth bound. A fresh-source run and certificate replay are separate checks.

Reproduce from the repository root:

```sh
python3 scripts/verify_atomic_referent_binding.py
```

The runner fails unless all ten positive obligations verify, the complete certificate rechecks, and both negative controls are falsified. It records commands, outcomes, the pre-instrumentation reference, and SHA-256 hashes in `proofs/verification_manifest.json`. The proof, logs, and counterexamples are in `proofs/`.

## Why this is the same protocol model

Compared with commit `4d823a783a57c80725adba0be2cf0f1fcb634ccf`, rule premises, state conclusions, network messages, signature terms, and the four original formulas are unchanged. Principal identity remains signed. No restriction on mutation, sessions, users, or attacker input was added.

The additions are trace-only events observing key/resource creation and version reads, plus proved helper lemmas and goal ordering. Actions do not enable or disable rules. Erasing the added events therefore maps each extended trace to the original trace; conversely, every original transition can be instrumented with those events without changing its premises or conclusions. The runner checks the relevant source-level equality for this theory's simple rule syntax. This is not a general Tamarin equivalence checker.

The `oracle` script only ranks proof goals; it supplies no axiom or acceptance verdict. Resource and version provenance support key secrecy and signature origin. The retirement proof suppresses unnecessary reuse of provenance lemmas to avoid expanding irrelevant creation histories. Every reused lemma is itself verified in the full run.

## Negative controls

- Remove only the signature input at Execute: `causal_authorization` is falsified.
- Remove the current-version premise and its corresponding state output at Execute: `no_execution_after_version_change` is falsified.

The broken variants import no helper lemmas. Their counterexamples test the relevance of these guards in this model, not necessity of two commitment roots or superiority over other protocols.

## Assumptions and limits

The issuer, private signing keys, version allocator, and atomic executor are trusted. Each mutation allocates a fresh, never-reused version identifier. Content is public and attacker-selected; mutation and session counts are unbounded in the symbolic model. Hashing and signatures use Tamarin's ideal symbolic algebra.

This proves properties of the transition model, not the Flutter UI, human attention, malicious-server resistance, concrete cryptographic implementations, wall-clock expiry, SQLite durability, remote-service atomicity, or hardware failures. Implementation conformance and empirical evaluation remain separate obligations. No novelty result follows from proof completion.

## Earlier diagnostic models

V2 removed identity from signed messages. At search bound 10 it verified executability and single execution but left causal authorization (314 steps) and version-change rejection (288 steps) incomplete. The globally single-mutation diagnostic also remained incomplete (214 and 45 steps respectively). Neither result establishes the cause of incomplete search. These variants are retained as diagnostics, not as the source of the current security result.

## Other theories

- `poia_protocol_baseline.spthy`: the unchanged eight-lemma core model; not a proof of database transactions or UI code.
- `kofn_confinement.spthy`: restricted abstract compromise model, not an implementation of independent processes or devices.
- `referent_state_integrity.spthy`: restricted mutation model; content equality alone does not imply version equality after restoration.
- `full_lifecycle_non_reconstitution.spthy`: its main lemma survived removal of second-root agreement in a review ablation; joint necessity is not established.

For k reports to include an honest report, f compromised roots must satisfy f < k. Availability additionally requires k <= n-f. The current implementation's two same-process functions are a consistency check, not independently compromised trust roots.
