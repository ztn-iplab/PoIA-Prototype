# Experiment 9: Structured Prompt Analysis Results

Current run: `usability-structured-confirmatory-05`

Superseded diagnostics: `usability-structured-confirmatory-02` and
`usability-structured-confirmatory-03`

## Method

Following the recorded protocol amendment, the deterministic analysis inspected
four domain intents and six single-field substitutions per domain on the current
WebAuthn and ZT-Authenticator display contracts. It measured semantic-field
presence, changed-value visibility, and the locus of review and cryptographic
action. It did not construct an aggregate usability score or compare backend
performance. No human participants were recruited.

## Results

| Approval surface | Visible fields | Visible substitutions | Browser intent modal | Semantic review locus | Cryptographic action locus | Full intent at application signing surface |
|---|---:|---:|---:|---|---|---:|
| WebAuthn | 35/35 | 24/24 | Shown | Relying-party browser modal | Platform WebAuthn ceremony | No |
| ZT-Authenticator | 35/35 | 24/24 | Hidden | Dedicated authenticator app dialog | Dedicated authenticator app dialog | Yes |

Both application-controlled surfaces displayed action, scope, principal,
relying party, workflow, and expiry, and all modeled changed values produced
distinguishable content. In the WebAuthn path, semantic review occurs in the
relying-party modal before the platform ceremony. In the ZT path, the dedicated
authenticator dialog retains the full semantic rendering beside the `Sign
intent` decision.

## Interpretation

The superseded `-02` run used an incomplete ZT text projection and could be
misread as a usability ranking. It is retained for provenance but excluded from
manuscript findings. The corrected result establishes deterministic content
availability and interaction architecture only. Completion rate, latency,
timeouts, false rejection, and user-mediated interaction cost remain pending
the 200 real operations per backend. The intermediate `-03` run predates the
source-bound browser-modal state check and is likewise excluded.

## Reproduction

```sh
PYTHONPYCACHEPREFIX=/tmp/poia-pycache \
  /private/tmp/poia-track-a-venv/bin/python \
  scripts/run_usability_structured_analysis.py \
  --run-id usability-structured-confirmatory-05
```

The run is immutable by identifier. Source commits and hashes are recorded in
the manifest; raw field and scenario rows, the summary, table, and SHA-256
checksums are under `experiments/usability_structured/`.
