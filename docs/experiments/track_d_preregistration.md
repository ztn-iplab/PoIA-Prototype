# Track D Pre-registration: Symbolic Formal Verification

Pre-registration date: 2026-06-20 (Asia/Tokyo)

## Objective

Verify the abstract PoIA authorization relation in Tamarin and preserve enough
metadata to reproduce every reported lemma interactively or in batch mode.

## Fixed Properties

The confirmatory model must contain and report:

1. `protocol_executable` (`exists-trace`) to establish a reachable honest
   approval and acceptance trace and guard against vacuous safety proofs.
2. `no_execution_without_matching_intent`.
3. `nonce_freshness`.
4. `replay_resistance`.
5. `intent_non_transferability`.
6. `context_confinement`.
7. `session_compromise_does_not_imply_execution`, with an explicit
   `CompromiseSession` premise.
8. `action_substitution_impossibility`.

Authentication-style lemmas must require approval or key reveal before server
acceptance. A key reveal after acceptance may not retroactively satisfy a
lemma. Intent issuance must precede acceptance.

## Model Scope

The model includes intent issuance, exact-tuple signing, registered public-key
verification, linear single-use intent state, session compromise, and explicit
signing-key reveal. It uses Tamarin's symbolic signing theory and perfect
cryptography assumption.

The model does not prove Python, Flutter, WebAuthn parsing, HTTP/TLS, database
transactions, UI rendering, canonical JSON, side-channel resistance, key
storage, or implementation equivalence. Those remain empirical or engineering
evidence classes.

## Confirmatory Procedure

- Require a clean repository tree and fixed commit.
- Record Tamarin and Maude versions, model and runner SHA-256 hashes, repository
  commit, command, start/end time, exit status, and wellformedness result.
- Execute `tamarin-prover --prove tamarin/poia_protocol.spthy`.
- Preserve complete stdout/stderr, a machine-readable lemma summary, Markdown
  threat-property table, run manifest, and checksum inventory.
- Treat `verified` as success only when Tamarin exits zero, reports successful
  wellformedness, and reports every fixed lemma as verified.

The run is invalid if any lemma is absent, falsified, unfinished, timed out, or
not reported, or if the executability lemma is not verified.

## Reporting

Report the Tamarin proof-step count for each lemma and map each safety property
to its relevant threat class. Do not translate symbolic verification into a
claim that the complete prototype or authenticator implementation is formally
verified.
