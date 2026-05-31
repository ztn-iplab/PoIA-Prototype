# PoIA Tamarin Lemma Notes

These notes explain the lemmas in `tamarin/poia_protocol.spthy` in manuscript
language. The detailed reproduction guide is in
`docs/experiments/tamarin_formal_verification.md`.

## no_execution_without_matching_intent

**Claim:** If the server accepts an operation, then the user must have approved
the same `(uid, action, scope, ctx, nonce)` tuple, unless the signing key was
explicitly revealed.

**Meaning:** A valid session or network-level access is not enough. Execution is
bound to a matching intent approval.

## nonce_freshness

**Claim:** If the server accepts an operation, then the same intent tuple must
have been issued by the server.

**Meaning:** The verifier does not accept proofs for injected or unissued
intents.

## replay_resistance

**Claim:** The same accepted tuple cannot be accepted twice.

**Meaning:** Reusing the same proof for the same nonce does not produce multiple
executions in the abstract model.

## intent_non_transferability

**Claim:** An approval for one action, scope, and context cannot authorize a
different action, scope, or context.

**Meaning:** Intent-bound proofs are not transferable across target objects,
parameters, or relying-party contexts.

## context_confinement

**Claim:** If an approval was made in one context, server acceptance for the same
operation must use that same context.

**Meaning:** A proof approved for one relying party, tenant, session, or API
audience cannot be replayed in another context.

## session_compromise_does_not_imply_execution

**Claim:** Server acceptance still requires matching approval or signing-key
compromise, even when session compromise is modeled.

**Meaning:** PoIA separates possession of a session token from possession of an
intent-signing capability.

## action_substitution_impossibility

**Claim:** Approval for one action cannot authorize another action.

**Meaning:** A proof for `transfer` cannot authorize `delete_user`, `rotate_key`,
or another substituted operation.
