# Manuscript Experimental-Design Evidence Map

This file maps the experimental-design section in `PoIA_Extended/Main.tex` to
the reproducible repository artifacts. The manuscript directory is local and
ignored; this map is the versioned trace record for the section.

## Study Protocol

- Controlling plan: `PoIA_Experimental_Validation_Plan.pdf`
- Pre-registration: `docs/experiments/track_a_preregistration.md`
- Implementation history: `docs/experiments/track_a_implementation_log.md`
- Real-backend operator protocol:
  `docs/experiments/track_a_real_backend_protocol.md`

## Track A

- Scenario corpus: `experiments/track_a/scenarios/security_effectiveness.json`
- Functional corpus: `experiments/track_a/scenarios/functional_correctness.json`
- Manifest and evidence utilities: `scripts/track_a_evidence.py`
- Manifest-bound recorder: `app/track_a_recorder.py`
- Progress validation: `scripts/track_a_run_status.py`
- Statistical analysis: `scripts/analyze_track_a.py`
- Verifier-only result: `docs/experiments/track_a_functional_results.md`
- Real WebAuthn and ZT results: pending 200-operation production-path runs

The verifier-only result must remain separate from authenticator interaction,
signature-generation, interoperability, and end-to-end latency claims.

## Extended Attack Paths

- Bearer-token cross-action reuse: `app/routes/poia.py` and
  `tests/test_token_reuse_http.py`
- Confused-deputy downstream enforcement: `app/downstream_client.py`,
  `downstream/main.py`, and `tests/test_downstream_ledger_http.py`
- Multi-step workflow binding: `app/routes/poia.py` and the Track A scenario
  corpus
- Atomic proof consumption and replay: `app/poia.py` and
  `tests/test_poia_execution_http.py`

## Tracks B-C

- Detailed designs: `docs/experiments/experiment_designs.md`
- Performance and comparative measurements remain pending unless a fixed run
  manifest and reviewed raw archive are cited.

## Track D

- Model: `tamarin/poia_protocol.spthy`
- Reproduction guide: `docs/experiments/tamarin_formal_verification.md`
- Runner: `scripts/run_tamarin_poia.sh`

## Track E

The real red-team and packet-capture exercise is pending execution in the
separate isolated virtual lab. Reportable artifacts must include:

- signed rules of engagement;
- legitimate and attack `.pcap` or `.pcapng` captures;
- mitmproxy/Burp flow or project exports;
- decision-log cross-reference keyed by `request_id`;
- pre/post protected-state snapshots; and
- exact tool versions and lab topology.

No Track E result may be inferred from application-unit tests or synthetic
requests on the development host. Raw tokens, private keys, and reusable
exploit material must not enter the public repository.
