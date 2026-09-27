# Combined-adversary extension of the composition theory

Extension of `../full_lifecycle_non_reconstitution.spthy`, which is left unchanged.
It admits a root compromise and a referent mutation in one trace and tests
whether each gate is necessary.

## Differences from the published composition theory
1. **Version binding.** The committed, displayed and signed intent is the pair
   `<v, h(content)>`. The execution gate requires the referent's current version to
   equal the signed `v` and its content to hash to the signed digest, as the paper's
   D_RSI requires. The published theory re-checks the digest only. Versions are fresh
   names, so each version identifies one referent; they are sent to the adversary.
2. **Budget.** Up to N adversarial actions per trace (root compromise and/or referent
   mutation) instead of one.
3. **Adversary-chosen substitution.** `Mutate_Referent` installs content taken from
   `In(...)`, so the attacker can substitute a record it controls (strictly stronger
   than the published fresh-content rule). The control variant keeps fresh content.

Honest capture, commitment, signing and execution are unbounded. Captured content
is a fresh name the adversary does not know before commitment; if captured content
were public, two root compromises would already exceed the 2-of-2 instantiation.

## Theories and expected outcomes
| Theory | Budget | Gates | Composed lemma | Other lemmas |
|---|---|---|---|---|
| composition_two_action | 2 | agreement + RSI | verified | ordered witness: mutation, then compromise whose report is signed and executed on the mutated referent (verified) |
| composition_two_action_no_agreement | 2 | RSI only | falsified | attack shape, in order: mutation to an attacker record, then a root reports its intent, which is signed and executes uncommitted (verified) |
| composition_one_action_no_rsi | 1 | agreement only | falsified | attack shape, in order: commitment, signing, mutation to a new version, execution of that version (verified) |
| composition_three_action | 3 | agreement + RSI | falsified | both roots compromised plus mutation, beyond 2-of-2 |
| composition_two_action_fresh_mutation_no_agreement | 2 | RSI only, fresh mutation | verified | control |

`composition_one_action_no_rsi` consumes the referent's state token on execution
instead of reproducing it; this only removes traces, so its attack traces are also
traces of the reproducing variant, and it keeps the search tractable.

Run: `sh run_all.sh` (needs `tamarin-prover` and `maude` on PATH; about 8 GB of
memory is enough).
