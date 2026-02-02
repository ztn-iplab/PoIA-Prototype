# PoIA Lemma Notes

This file provides short, explanations for each lemma in `poia_protocol.spthy`.

## authorization
**Claim:** Any server acceptance must be backed by a genuine user approval (or explicit key compromise).  
**Meaning:** An attacker cannot authorize an intent without a valid approval signature from the enrolled device key.

## intent_binding
**Claim:** Every accepted authorization corresponds to an intent that was actually issued by the server.  
**Meaning:** The system does not accept approvals for unissued or injected intents.

## replay_resistance
**Claim:** A specific intent tuple `(uid, action, scope, nonce)` can be accepted at most once.  
**Meaning:** Replaying the same approval does not yield multiple successful authorizations.

## approval_requires_intent
**Claim:** A valid approval implies a corresponding issued intent.  
**Meaning:** The user’s device will only sign and approve intents that were issued by the system.
