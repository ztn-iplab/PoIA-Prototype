# Track A: Attack Success and Functional Correctness

This directory contains confirmatory Track A inputs and, after execution, the
raw evidence used to generate manuscript results. The protocol is frozen in
`docs/experiments/track_a_preregistration.md`.

Prepare a run before starting the relying party or issuing any trial:

```bash
python3 scripts/prepare_track_a_run.py \
  --configuration session_only \
  --batch-id session-only-01 \
  --seed 20260620
```

The command validates every scenario, creates a run directory under `raw/`,
and writes a sanitized manifest. It does not run an experiment. The printed
`run_id` must be supplied to the later trial runner so every request, decision,
snapshot, and timing record can be joined.

For a real WebAuthn legitimate-action batch, start the application with the
container-visible manifest path and an explicit expected decision:

```bash
export POIA_TRACK_A_MANIFEST=/experiments/track_a/raw/<run_id>/manifest.json
export POIA_TRACK_A_SCENARIO_ID=exact_legitimate_match
export POIA_TRACK_A_EXPECTED_DECISION=accept
export POIA_TEST_MODE=false
./run.sh --build
```

The execution gate automatically appends one JSONL decision and one pre/post
state snapshot per completed operation. Browser-driven attempts receive
monotonic attempt numbers. Automated harnesses may provide
`X-PoIA-Request-Id`, `X-PoIA-Attempt`, `X-PoIA-Scenario-Id`,
`X-PoIA-Scenario-Category`, and `X-PoIA-Expected-Decision` headers.

Generate an honest progress table at any point:

```bash
python3 scripts/analyze_track_a.py \
  experiments/track_a/raw/<run_id> --allow-incomplete
```

Omit `--allow-incomplete` for the final table. Final analysis refuses to run
unless there are exactly 200 uniquely numbered decisions. A measured zero is
reported with its Wilson 95% confidence interval, never as an unsupported bare
`0%`.

Generated run data is intentionally excluded from Git until it has been
reviewed for secrets and assigned an artifact checksum. Scenario definitions,
schemas, analysis code, and empty directory placeholders remain versioned.

## Directory Contract

- `scenarios/`: immutable, declarative scenario definitions.
- `schemas/`: JSON Schemas for definitions, manifests, and decisions.
- `manifests/`: reviewed copies of frozen run manifests.
- `raw/<run_id>/`: unreviewed local evidence from one run.
- `decisions/`: reviewed structured decision logs.
- `state_snapshots/`: reviewed pre/post state evidence.
- `analysis/`: versioned analysis outputs and checksums.
- `tables/`: manuscript-ready tables generated from reviewed raw data.
- `figures/`: manuscript-ready figures generated from reviewed raw data.

Never store cookies, bearer tokens, private keys, raw signatures, password
material, authenticator secrets, or direct personal identifiers in these
artifacts.
