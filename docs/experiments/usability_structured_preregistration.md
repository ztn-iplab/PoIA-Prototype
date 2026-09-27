# Experiment 9 Pre-registration: Structured Prompt Analysis

Pre-registration date: 2026-06-21 (Asia/Tokyo)

## Research Question

Do the current WebAuthn and ZT-Authenticator approval surfaces expose the
security-relevant intent fields needed to distinguish exact operations from
action, target, value, principal, relying-party, and workflow substitutions?

## Scope

This is a deterministic structured interface analysis, not a participant study.
It cannot measure comprehension, confusion, approval time, preference, or
habituation. Those outcomes remain pending a controlled human study.

## Fixed Corpus

Inspect banking transfer, enterprise role grant, healthcare record export, and
cloud key rotation. For each domain, compare an exact intent with six single-
field substitutions: action, target, value or privilege, principal, relying
party, and workflow. Evaluate both production display contracts:

- WebAuthn browser modal in `app/templates/base.html`;
- ZT-Authenticator dialog in `mobile/lib/main.dart`.

The mobile source commit is recorded in the manifest but remains unmodified by
this experiment.

## Metrics

- visible-field coverage for action, scope, principal, RP, and workflow;
- mutation visibility: whether approved and changed renderings differ and the
  changed value is visible;
- explicit action, RP, and expiry indicators;
- rendered character count and line count; and
- vague-only prompt count.

Nonce and proof hashes are machine-verification fields and are not required to
be displayed as user-facing semantics.

## Validity and Artifacts

Use a clean PoIA tree, fixed run identifier, source hashes, raw field-level
rows, scenario rows, summary, table, manifest, and SHA-256 checksums. Existing
files under `experiments/usability_structured/` are exploratory and excluded.

## Interpretation Limit

Passing content coverage means the information is present in the deterministic
rendering contract. It does not show that users notice, understand, remember,
or correctly act on that information. A missing field is a concrete interface
coverage finding, not an estimated human error rate.
