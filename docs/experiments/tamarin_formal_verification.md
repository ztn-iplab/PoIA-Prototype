# Experiment 8: Tamarin Formal Verification

## Goal

The Tamarin model gives symbolic evidence for the core PoIA security claim:
server execution requires a matching user-approved intent-bound proof.

The model is intentionally abstract. It does not model the whole banking
application, HTTP, browser UI, database storage, or a concrete WebAuthn ceremony.
It models the authorization core:

```text
issue intent -> user signs same intent -> server accepts only matching signed intent
```

## Files

The model is here:

```text
tamarin/poia_protocol.spthy
```

The helper runner is:

```text
scripts/run_tamarin_poia.sh
```

Generated proof output is written to:

```text
tamarin/results/poia_protocol.txt
experiments/formal_verification_expansion/tamarin_output.txt
```

The experiment table is:

```text
experiments/formal_verification_expansion/formal_verification_table.md
```

## Model Vocabulary

The intent tuple is:

```text
<uid, action, scope, ctx, nonce>
```

Where:

- `uid`: user identity
- `action`: high-risk operation, for example transfer or rotate key
- `scope`: target object and parameters
- `ctx`: relying-party or execution context
- `nonce`: freshness value

The approval proof is:

```text
sign(<uid, action, scope, ctx, nonce>, sk)
```

The public key fact is:

```text
!UserPub(uid, pk(sk))
```

## Rules

### `Init_User`

Creates a user signing key and public key.

```text
Fr(uid), Fr(sk) -> !UserKey(uid, sk), !UserPub(uid, pk(sk))
```

This represents registration of a device-bound signing key.

### `Issue_Intent`

Creates a fresh intent and publishes the tuple.

```text
IssueIntent(uid, action, scope, ctx, nonce)
Intent(uid, action, scope, ctx, nonce)
!IntentIssued(uid, action, scope, ctx, nonce)
```

`Intent` is linear, so it is consumed by acceptance. This is what supports the
single-use replay-resistance lemma in the abstract model.

### `User_Approve`

The user/device signs exactly the issued tuple.

```text
ApproveIntent(uid, action, scope, ctx, nonce)
Out(<uid, action, scope, ctx, nonce, signature>)
```

This abstracts WebAuthn, ZT-Authenticator, or another signing backend.

### `Server_Accept`

The server consumes the matching intent and accepts only if the signature
verifies under the user's registered public key.

```text
Eq(verify(sig, <uid, action, scope, ctx, nonce>, pk), true)
ServerAccept(uid, action, scope, ctx, nonce)
```

The model includes an equality restriction:

```text
restriction Equality:
  "All x y #i. Eq(x, y) @ #i ==> x = y"
```

This is the standard way this model turns an `Eq(...)` action fact into a proof
constraint. The current model proves with all wellformedness checks successful.

### `Compromise_Session`

Outputs a session token but not the signing key.

This separates session compromise from signing-key compromise. The model uses it
to express the PoIA claim that stealing a session alone is insufficient for
execution.

### `Reveal_Key`

Explicitly reveals the user's signing key. Several lemmas include this as an
exception because if the signing key is compromised, the attacker can create
valid signatures in the symbolic model.

## Lemmas

| Lemma | Meaning |
|---|---|
| `no_execution_without_matching_intent` | Server acceptance implies matching approval, unless the signing key was revealed. |
| `nonce_freshness` | Server acceptance implies a matching issued intent existed. |
| `replay_resistance` | The same accepted intent tuple cannot be accepted twice. |
| `intent_non_transferability` | Approval for one action/scope/context cannot authorize a different action/scope/context. |
| `context_confinement` | Approval in one context cannot authorize execution in another context. |
| `session_compromise_does_not_imply_execution` | Session compromise alone is not enough; execution still needs approval or key compromise. |
| `action_substitution_impossibility` | Approval for one action cannot authorize a different action. |

## Batch Reproduction

From the repository root:

```bash
./scripts/run_tamarin_poia.sh
```

Or regenerate the experiment artifact:

```bash
python3 scripts/generate_formal_verification_artifacts.py --out-dir experiments/formal_verification_expansion --run-tamarin
```

Expected result:

```text
All wellformedness checks were successful.
no_execution_without_matching_intent: verified
nonce_freshness: verified
replay_resistance: verified
intent_non_transferability: verified
context_confinement: verified
session_compromise_does_not_imply_execution: verified
action_substitution_impossibility: verified
```

## Interactive Testing

To inspect the proof interactively:

```bash
tamarin-prover interactive tamarin/poia_protocol.spthy
```

Then open the URL printed by Tamarin, usually:

```text
http://127.0.0.1:3001
```

In the browser:

1. Select `PoIA_Protocol`.
2. Choose one lemma, such as `action_substitution_impossibility`.
3. Use autoprove to reproduce the proof.
4. Inspect the rule graph to see how `Issue_Intent`, `User_Approve`, and
   `Server_Accept` constrain the trace.

Useful manual checks:

- Try `replay_resistance` and observe that the linear `Intent` fact prevents two
  accepts of the same tuple.
- Try `context_confinement` and inspect where Tamarin forces `ctx = ctx2`.
- Try `session_compromise_does_not_imply_execution` and confirm that
  `CompromiseSession` does not output `sk`.

## How This Connects to the Paper

The Tamarin model supports the formal side of the paper. It does not prove every
implementation detail of the Python prototype. Instead, it proves that the
abstract PoIA authorization relation has the desired Intent Integrity properties
under the symbolic signing model.

The Python experiments complement this by showing the same logic across attack
scenarios, domains, OAuth/API authorization, audit logs, and parameter choices.
