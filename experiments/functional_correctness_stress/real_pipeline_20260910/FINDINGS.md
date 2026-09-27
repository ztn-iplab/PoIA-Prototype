# Findings from the real-pipeline functional-correctness run (2026-09-10)

## Result
1,800 cases against the production pipeline (`app.core.create_poia_intent` ->
`poia_store.approve_proof` -> `poia_store.reserve_execution`, canonicalization by
`app.intent_codec.canonical_json`). 600 valid / 1,200 invalid. FAR 0.0%, FRR 0.0%,
zero disagreements with an independently written normalizer.

## Observation: malformed serialization rejects by exception, not by typed denial

Every other reject category returns a first-class reason from the gate
(`action_mismatch`, `scope_mismatch`, `rp_mismatch`, `expired`, `proof_consumed`).
Malformed serialization is different: `app.intent_codec.normalize_intent_value`
**raises**, and the request never reaches a gate decision.

Observed exceptions:
- `ValueError: intent numbers must be finite` (NaN / Infinity)
- `ValueError: intent contains keys that collide after Unicode normalization`
- `TypeError: unsupported intent value type: bytes`
- `TypeError: intent object keys must be strings`

At the HTTP layer `app/main.py` installs a catch-all
`@app.exception_handler(Exception)` returning `500 {"error": "internal_error"}`
and logging "Unhandled request error".

**Security assessment: correct.** The behavior is fail-closed - no protected
execution occurs, so the manuscript's "Malformed serialization -> Reject" row is
accurate at the enforcement level.

**Two caveats worth stating in the paper rather than leaving implicit:**
1. A malformed-input rejection is indistinguishable from a genuine server fault
   in the HTTP response (both are `500 internal_error`).
2. It is recorded in logs as an unhandled error rather than as a policy denial,
   so it does not appear in the authorization audit trail the way other
   rejections do. This is relevant to the forensic-reconstruction claims: a
   malformed-input attack is not reconstructable from the denial record.

Neither is a vulnerability. Both are accuracy points: the table row is earned by
fail-closed behavior, not by a typed rejection path.
