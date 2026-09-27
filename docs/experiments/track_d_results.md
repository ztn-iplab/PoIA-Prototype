# Track D Symbolic Verification Results

Run ID: `track-d-confirmatory-02`

Frozen commit: `fe5b85c3804c6f7cfff49d0decb7073f525c4c13`

Toolchain: Tamarin Prover 1.12.0 and Maude 3.5.1.

Tamarin exited successfully, reported successful wellformedness, and verified
all eight pre-registered lemmas:

| Lemma | Result |
|---|---|
| `protocol_executable` | verified (9 steps) |
| `no_execution_without_matching_intent` | verified (7 steps) |
| `nonce_freshness` | verified (3 steps) |
| `replay_resistance` | verified (10 steps) |
| `intent_non_transferability` | verified (14 steps) |
| `context_confinement` | verified (5 steps) |
| `session_compromise_does_not_imply_execution` | verified (8 steps) |
| `action_substitution_impossibility` | verified (5 steps) |

The executability lemma demonstrates a reachable honest approval and acceptance
trace, preventing the safety results from being accepted solely because server
acceptance is unreachable. Operation fields are public inputs rather than fresh
unguessable values. Approval, intent issuance, and key-reveal exceptions are
causally ordered before acceptance, and the session-compromise lemma explicitly
requires a prior `CompromiseSession` event.

The model proves the abstract authorization relation under Tamarin's symbolic
signing theory. It does not formally verify canonical JSON, Python or Flutter
code, WebAuthn parsing, HTTP/TLS, database atomicity, user-interface rendering,
side channels, or secure key storage.

The full output, summary, threat-property table, manifest, and checksum
inventory are under `experiments/formal_verification_expansion/`. Interactive
reproduction uses:

```bash
tamarin-prover interactive tamarin/poia_protocol.spthy
```
