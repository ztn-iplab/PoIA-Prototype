# Track B: Comparative Authorization Baselines

Track B executes the same attack corpus against session-only authorization,
generic MFA confirmation, fixed-field transaction confirmation, and exact PoIA
intent binding. The controlling protocol is
`docs/experiments/track_b_preregistration.md`.

From a clean, committed repository, run:

```bash
python3 scripts/run_track_b_comparative.py \
  --trials 200 \
  --seed 20260620 \
  --run-id track-b-confirmatory-01
```

The runner refuses a dirty repository unless `--allow-dirty` is supplied.
Outputs created with that override are diagnostics and must not be cited.

Each run writes a manifest, 5,600 raw JSONL/CSV attack observations, a summary
with Wilson 95% confidence intervals, and a Markdown results table under
`experiments/track_b/raw/<run-id>/`.
