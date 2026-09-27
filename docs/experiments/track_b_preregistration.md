# Track B Pre-registration: Comparative Authorization Baselines

Status: design frozen; no reportable Track B trials may run until this file and
the executable gates are committed.

## Claim And Configurations

Track B operationalizes the manuscript comparison across four gates applied to
the same workload: `session_only`, `mfa_confirmation`,
`transaction_confirmation`, and `poia_exact_intent`.

- Session-only checks authenticated session state only.
- MFA confirmation records recent user presence but binds no operation fields.
- Transaction confirmation binds principal, action, amount, and beneficiary,
  but not relying-party, delegation, tenant, or workflow context.
- PoIA binds the complete canonical intent and consumes approval once.

## Fixed Design

- Scenarios: the seven cases in
  `experiments/track_b/scenarios/comparative_baselines.json`.
- Sample size: 200 attack attempts per scenario per configuration.
- Legitimate controls: 200 per configuration, reported separately.
- Seed: `20260620` unless a manifest records a pre-run replacement.
- Attack success: an adversarial request is accepted and changes protected
  state.
- Binary intervals: two-sided Wilson 95% confidence intervals.
- Latency: median, IQR, P95, and P99 from per-attempt measurements.

## Outcomes

Primary outcomes are attack acceptance, correct rejection, false acceptance,
false rejection, rejection reason, and protected-state change. Derived Table
VIII metrics are field-tampering rejection, replay acceptance, cross-action
reuse rejection, combined authorization correctness, and audit-trace field
completeness.

## Interpretation Limits

These gates are executable semantic baselines, not measurements of every
commercial MFA or transaction-signing product. Real WebAuthn and
ZT-Authenticator interaction latency remains in the separate Track A manual
runs. Track B results cannot be merged with pilot data or reported until the
repository commit and raw run manifest are frozen.
