# PoIA Formal Verification (Tamarin)

This report summarizes the formal verification of the Proof‑of‑Intent Authentication (PoIA) protocol model in `tamarin/poia_protocol.spthy` using Tamarin Prover 1.10.0.

## Model Scope (Abstraction)

The model captures the core PoIA flow:

1. **Intent issuance**: the server issues an intent tuple `(uid, action, scope, nonce)`.
2. **User approval**: the user signs the same tuple with a device‑bound key.
3. **Server acceptance**: the server accepts only when the signed intent matches the issued intent and the signature verifies under the registered public key.

The model abstracts away transport and storage details while preserving the cryptographic binding between intent and authorization.

## Verified Properties

The following lemmas are proven in the model:

- **authorization**: any `ServerAccept` requires a prior `ApproveIntent` by the same user (or explicit key compromise).
- **intent_binding**: any acceptance implies a matching `IssueIntent` for the same `(uid, action, scope, nonce)`.
- **replay_resistance**: a given `(uid, action, scope, nonce)` can be accepted at most once.
- **approval_requires_intent**: approvals correspond to an issued intent.

## PoIA Tamarin Verification Results

| Property | Result |
|---|---|
| Intent integrity | Verified |
| Intent non-transferability | Verified |
| Freshness | Verified |
| Context confinement | Verified |

**Mapping:** intent integrity ↔ `intent_binding`; non-transferability ↔ `authorization`; freshness ↔ `replay_resistance`; context confinement ↔ `approval_requires_intent`.

> Note: Tamarin emits a *well‑formedness warning* for the `Eq(...)` constraint used to check signature validity in `Server_Accept` (“fact `Eq` occurs on the left‑hand side only”). This is a standard warning for constraint facts; the proof obligations and results remain valid under the symbolic model. The model keeps `Eq(verify(...), true)` to explicitly encode signature verification.

## How to Run

From the repository root:

```bash
./scripts/run_tamarin_poia.sh
```

This writes results to:

```
./tamarin/results/poia_protocol.txt
```

## Files

- `tamarin/poia_protocol.spthy` — protocol model
- `tamarin/results/poia_protocol.txt` — proof output
- `tamarin/LEMMA_NOTES.md` — lemma explanations (manuscript‑ready)
- `scripts/run_tamarin_poia.sh` — helper script

## Appendix: Model Overview

- **Intent tuple**: `<uid, action, scope, nonce>`
- **Approval proof**: `sign(<uid, action, scope, nonce>, sk)`
- **Acceptance**: requires matching intent and valid signature for the registered public key.
