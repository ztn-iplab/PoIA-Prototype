# PoIA Formal Verification Report

This report summarizes the current Tamarin model for Proof-of-Intent
Authentication (PoIA). The model is located at:

```text
tamarin/poia_protocol.spthy
```

For a step-by-step reproduction and interactive testing guide, see:

```text
docs/experiments/tamarin_formal_verification.md
```

## Model Scope

The model captures the PoIA authorization core:

1. The server issues an intent tuple `(uid, action, scope, ctx, nonce)`.
2. The user approves by signing exactly that tuple with a device-bound key.
3. The server accepts only when the proof verifies for the same tuple and the
   corresponding issued intent exists.

The model abstracts away the web UI, storage, HTTP, and concrete WebAuthn
ceremony. It preserves the cryptographic binding between user approval and
server execution.

## Verified Lemmas

| Lemma | Result |
|---|---|
| `no_execution_without_matching_intent` | Verified |
| `nonce_freshness` | Verified |
| `replay_resistance` | Verified |
| `intent_non_transferability` | Verified |
| `context_confinement` | Verified |
| `session_compromise_does_not_imply_execution` | Verified |
| `action_substitution_impossibility` | Verified |

The current proof run reports:

```text
All wellformedness checks were successful.
```

## How to Run

From the repository root:

```bash
./scripts/run_tamarin_poia.sh
```

This writes proof output to:

```text
tamarin/results/poia_protocol.txt
```

To regenerate the formal verification experiment table:

```bash
python3 scripts/generate_formal_verification_artifacts.py --out-dir experiments/formal_verification_expansion --run-tamarin
```

## Interactive Mode

To inspect proofs manually:

```bash
tamarin-prover interactive tamarin/poia_protocol.spthy
```

Open the URL printed by Tamarin and select individual lemmas for autoprove or
manual trace inspection.
