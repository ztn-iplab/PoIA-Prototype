# Experiment 9 Protocol Amendment: Approval-Surface Interpretation

Amendment date: 2026-06-21 (Asia/Tokyo)

## Reason

Review of run `usability-structured-confirmatory-02` identified a construct-
validity problem. The analysis correctly counted fields in its modeled text
projections, but the resulting percentages could be read as comparative
usability or backend performance. That inference is unsupported because the
two backends use different interaction architectures: WebAuthn presents the
full intent in the relying-party browser modal before invoking the platform
ceremony, whereas ZT-Authenticator presents the intent and signing decision in
a dedicated mobile application dialog.

The prior run is retained as a superseded diagnostic. It must not be cited as
evidence that WebAuthn is more usable, clearer, faster, or operationally better
than ZT-Authenticator.

## Post-diagnostic Refinement

The ZT-Authenticator approval dialog was refined to render all supplied context
fields with readable labels, use a scrollable layout for larger intents, and
label the positive decision `Sign intent`. Enrollment, polling, canonicalization,
intent hashing, signing, replay handling, and server verification were not
changed. The authenticator commit is recorded in the next run manifest.

## Corrected Outcomes

The amended static analysis reports:

- semantic field presence and single-field mutation visibility for each
  approval surface;
- explicit approve/sign and deny controls;
- the locus of semantic review and cryptographic action; and
- whether the application controls a full semantic rendering at the final
  signing-decision surface.

It reports no aggregate usability score and does not rank the backends. Text
length and line count are removed because browser DOM and Flutter widgets are
not comparable plain-text layouts.

## Pending Comparative Evidence

Backend latency, completion rate, timeout rate, false rejection, interaction
cost, and user-mediated approval time remain pending the 200 real WebAuthn and
200 real ZT-Authenticator operations. Those measurements must come from the
production paths and may not be inferred from this static analysis.
