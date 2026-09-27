# Track B Comparative Baseline Results

> **Note on paths in this directory.** Documents here describe the experiment
> designs and the runs recorded at the time of writing. Result packages named
> after superseded runs were removed in the 2026-09-10 evidence reset and are
> not in this repository; `REPRODUCTION.md` lists the packages the manuscript
> actually reports and the runner that regenerates each one.

Run ID: `track-b-confirmatory-02`

Frozen commit: `8d0221b6b975ba46a2f1073f08f685d1c9813cf8`

The clean confirmatory run contains 5,600 attack observations (seven scenarios,
four gates, 200 attempts per cell) and 800 separately analyzed legitimate
controls (200 per gate). All legitimate controls were accepted: 200/200 per
configuration, Wilson 95% CI 98.12-100.00%, with zero false rejections.

Across all seven attacks:

| Gate | Successful attacks | Attack success, Wilson 95% CI |
|---|---:|---:|
| Session-only | 1400/1400 | 100.00%, 99.73-100.00% |
| Generic MFA confirmation | 1400/1400 | 100.00%, 99.73-100.00% |
| Fixed-field transaction confirmation | 800/1400 | 57.14%, 54.53-59.71% |
| Exact PoIA intent binding | 0/1400 | 0.00%, 0.00-0.27% |

Fixed-field transaction confirmation blocked replay, amount tampering, and
cross-action reuse, but accepted substitutions in relying-party context,
session context, delegation identity, and workflow identity because those
fields were outside its confirmation schema. PoIA rejected every mutation by
binding and consuming the complete canonical intent.

The latency columns measure local gate-decision cost only. They do not include
network, browser, authenticator, or human interaction and must not be used as
Track C end-to-end latency evidence.

Reviewed artifacts are under `experiments/track_b/`; the full raw archive is
local and its hashes are frozen in
`experiments/track_b/analysis/track-b-confirmatory-02-checksums.sha256`.
