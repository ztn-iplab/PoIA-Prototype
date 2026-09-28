# PoIA — Proof-of-Intent Authorization

Research artifact for:

> **Proof-of-Intent Authorization (PoIA): Enforcing
Intent Integrity from Commitment to Execution**
> Patrick Mutabazi, Festus Edward Ndalama, Yuzo Taenaka, and Youki Kadobayashi
> Laboratory for Cyber Resilience, Nara Institute of Science and Technology (NAIST)

This repository holds the relying-party prototype, the symbolic models, the
evaluation harness, and the recorded measurements behind every number the paper
reports. The companion signing application is at
[ztn-iplab/ZT-Authenticator](https://github.com/ztn-iplab/ZT-Authenticator).

> **This is a research prototype.** It exists to make the paper's claims
> checkable, not to be deployed. It has not been security-reviewed for
> production use, and its demonstration banking application is deliberately
> simple.

## What the artifact establishes

Authentication answers *who is present*. It does not answer whether the
high-impact operation about to execute is the one the user reviewed. PoIA
permits a protected operation only when a fresh, single-use proof over a
canonical intent is valid and the normalized execution semantics equal those of
the signed intent. Two further conditions close the lifecycle:

| Condition | What it requires |
| --- | --- |
| Intent Integrity | A fresh single-use proof over the canonical intent, and execution semantics equal to the signed ones |
| Referent-State Integrity | Referenced content still carries its committed version and digest, re-checked inside the transaction that performs the effect |
| *k*-of-*n* Independent Commitment Confinement | At least *k* of *n* independent construction paths agree on a value before it is signed |
| Full-Lifecycle Non-Reconstitution | The composition of the above across capture, commitment, display, signing, and execution |

## Layout

```
app/              relying party: verifier, canonicalization, gates, demo banking UI
downstream/       separate service used for the distributed-execution experiments
formal-models/    Tamarin theories, proof outputs, and the verification runner
scripts/          experiment runners, analysis, and figure generation
experiments/      recorded inputs, raw measurements, summaries, and checksums
docs/experiments/ per-experiment design, preregistration, and results
tests/            unit and HTTP tests for the verifier and the demo application
```

## Running the prototype

Dependencies are pinned in `requirements.txt`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload      # http://127.0.0.1:8000
```

Passkeys require a secure context, so WebAuthn does not work over plain HTTP.
For the full flow, `./run.sh` brings up the application behind nginx over HTTPS
at `https://poia.local` using Podman. On first run it generates a lab-only
certificate authority and a `poia.local` certificate into `certs/` and
`private/`; both directories are ignored by git and no trust material ships with
this repository.

Configuration comes from a `.env` file, which is also ignored. Copy
`.env.example` and set your own values:

```bash
cp .env.example .env
# set POIA_SESSION_SECRET and POIA_DOWNSTREAM_SECRET to fresh random strings,
# e.g. openssl rand -hex 32, and choose your own POIA_ADMIN_EMAIL and
# POIA_ADMIN_PASSWORD. No default administrator credential is shipped.
```

## Reproducibity

`docs/experiments/REPRODUCTION.md` is the single entry point. It maps each
reported result to its retained inputs, its runner, and its recorded output, and
records the scope of every run — which experiments call the gate functions
directly, which instantiate the in-memory state machine, and which are
standalone cryptographic benchmarks.

Check that nothing has been altered since the runs that produced it. The first
command verifies every file in the release against `RELEASE_CHECKSUMS.sha256`;
the second verifies each experiment package against the checksum manifest its
own run recorded; the third confirms that the evidence register in
`REPRODUCTION.md` still matches the files on disk:

```bash
sha256sum -c RELEASE_CHECKSUMS.sha256
python3 scripts/verify_artifact_checksums.py
python3 scripts/check_journal_evidence.py
```

None of these is a fresh proof search or a re-measurement; they establish file
identity only.

Re-run the symbolic verification (Tamarin 1.12.0, Maude 3.5.1). The three
restricted theories need no oracle, and the runner asserts all twelve
obligations against the outcomes the paper reports, exiting non-zero on any
mismatch:

```bash
python3 formal-models/verify_restricted_theories.py
```

The harness controls are in
`experiments/functional_correctness_stress/_harness_validation/` and
`experiments/protocol_vectors/attack_outcomes/_harness_validation/`: deliberate
mutations of the verifier that must produce their prescribed failures — 100%
false acceptance when the gate always accepts, 100% false rejection when it
always rejects, and 66.67% false rejection when normalization is disabled.

Each experiment directory carries its raw measurements, a machine-readable
summary, a Markdown table, a manifest, and SHA-256 checksums. Reported latencies
are local measurements, so absolute timings vary by machine; the
security and correctness decisions should not.

## What is not in this repository

- **Participant records.** The paper makes no confirmatory human-behavioural
  claim, and the consent obtained does not cover open publication of
  participant-level responses, so neither the responses nor the study
  instruments are released.
- **Trust material.** No certificate, private key, or `.env` is committed. The
  lab CA is generated locally on first run.
- **A network-capture exercise.** Every adversarial result reported is a
  controlled semantic-effect test against the verifier. None is a deployment
  against live malware, and none should be read as one.

## Citing

A `CITATION.cff` file is included. Please cite the journal paper; until it
appears, cite the conference paper that introduced PoIA:

> P. Mutabazi, F. E. Ndalama, Y. Taenaka, and Y. Kadobayashi,
> "Proof-of-Intent Authorization (PoIA): Cryptographic Binding of Verified
> Intent to Action Semantics," in *Proc. 2026 10th Int. Conf. Cryptography,
> Security and Privacy (CSP)*, Sapporo, Japan, Apr. 2026.

## Licence

Released under the MIT Licence. See [LICENSE](LICENSE).
