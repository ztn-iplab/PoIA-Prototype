# PoIA Formal Verification Expansion

## Lemma Result Table

| Lemma | Property | Threat Mapping | Result |
|---|---|---|---|
| `no_execution_without_matching_intent` | No execution without matching intent | Session misuse, missing proof | verified (7 steps) |
| `nonce_freshness` | Nonce freshness / issued intent existence | Injected or unissued intent | verified (3 steps) |
| `replay_resistance` | Replay resistance | Proof replay | verified (10 steps) |
| `intent_non_transferability` | Intent non-transferability | Intent/scope substitution | verified (14 steps) |
| `context_confinement` | Context confinement | Wrong RP/session/tenant context | verified (5 steps) |
| `session_compromise_does_not_imply_execution` | Session compromise does not imply execution | Stolen session | verified (7 steps) |
| `action_substitution_impossibility` | Action substitution impossibility | Cross-action reuse | verified (5 steps) |

## Repository Reproducibility

Run from the repository root:

```bash
./scripts/run_tamarin_poia.sh
```

Expanded model:

```text
tamarin/poia_protocol.spthy
```

Tamarin status: `proof output written to experiments/formal_verification_expansion/tamarin_output.txt`
Wellformedness: `successful`
