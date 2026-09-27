# Track C Performance and Scalability

Track C1 is the isolated server-side protocol microbenchmark defined in
`docs/experiments/track_c_preregistration.md`.

Run from a clean fixed commit:

```bash
PYTHONPYCACHEPREFIX=/tmp/poia-pycache \
  /private/tmp/poia-track-a-venv/bin/python scripts/run_track_c_performance.py \
  --run-id track-c-confirmatory-01
```

Raw per-operation evidence is written below `raw/<run-id>/` and ignored by
Git. The reviewed manifest, summary, Markdown table, and checksum inventory are
versioned in their corresponding directories. Private signing keys exist only
in memory while the runner is active.

This runner measures software protocol paths. It does not measure browser,
handset, secure-hardware, network, or user interaction latency.
