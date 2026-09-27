# ZT Intent Hash Interoperability Incident

## Scope

On 2026-06-20, live ZT-Authenticator approvals for amount-bearing intents were
rejected with `hash_mismatch`. The pre-fix telemetry contains repeated rejected
approvals for user 3 and intent IDs `n4DfnwwHMT7rn1T3`,
`2IZvf4nKnle_qHU1`, and `jNgeNpcHXKsOorUE`. No proof was accepted or consumed
in these sequences. The raw telemetry remains in the local container data
volume and is excluded from the confirmatory datasets.

## Root Cause

The mobile client reconstructed the proof hash from the JSON intent. The server
canonicalizer normalizes an integral floating-point value such as `50.0` to
`50`, while Dart's JSON encoder retained `50.0`. The two byte strings therefore
produced different hashes even though they represented the same intent.

## Correction

The pending-intent endpoint already returns the server-computed proof hash in
`intent_hash`. The mobile client now requires and signs that exact value. It no
longer implements an independent canonicalizer in the approval path. The bank
still recomputes the hash from its stored intent, nonce, and expiry and rejects
a substituted value before signature verification.

The cross-implementation regression vector is
`experiments/protocol_vectors/zt_intent_hash_v1.json`. It explicitly covers the
integral-float representation that exposed the defect.

## Experimental Treatment

These failed attempts are engineering diagnostics, not Track A or Track C
observations. Confirmatory runs must use a build containing the correction and
must record the application and authenticator commit identifiers in the run
manifest. A `replay` response remains correct for a proof that has already left
the pending state; it is distinct from this pre-verification hash mismatch.
