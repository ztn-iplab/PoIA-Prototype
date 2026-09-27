# Current Core PoIA Verification

This fresh local run verifies the eight-lemma signed-intent model presented in
the manuscript. Seven safety properties and one executability property passed;
Tamarin reported successful wellformedness checks.

The copied `poia_protocol.spthy` is the exact source for this run. The JSON
summary, transcript, and table record the results. This package does not reuse
an earlier transcript and does not assert that any earlier eight-lemma run was
part of the conference publication.

Reproduce from the repository root:

```sh
tamarin-prover --prove experiments/formal_verification_expansion/core-protocol-alignment/poia_protocol.spthy
```

The model binds issued intent, user approval, and server acceptance. It does not
prove independent original-task capture, human attention, display integrity,
wall-clock expiry, or correctness of concrete database or transport code.
The sibling `end-to-end-alignment` folder is a withdrawn nine-lemma variant,
not evidence for the current manuscript.
