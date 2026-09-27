#!/usr/bin/env python3
"""Turn a live approval-latency summary into manuscript-ready output.

Consumes approval_latency_summary.json from analyze_live_approval_timing.py and
produces (a) fig:latency in the same visual style as verification_throughput.pdf
and (b) the exact LaTeX strings for tab:latency, the RQ5 prose, and the
eligible-sample/exclusion accounting. Reports seconds, because tab:latency is
headed in seconds while the analyzer emits milliseconds.

Refuses to emit a P99 that is not estimable from the sample size.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MIN_N_FOR_P99 = 100  # below this, the 99th percentile is essentially the maximum


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True, type=Path)
    ap.add_argument("--baseline-ms", type=float, default=0.0110,
                    help="Local session-check cost (default: measured 0.0110 ms)")
    ap.add_argument("--figure-out", type=Path, default=Path("PoIA_Extended/poia_latency.pdf"))
    ap.add_argument("--no-figure", action="store_true")
    a = ap.parse_args()

    d = json.loads(a.summary.read_text(encoding="utf-8"))
    by = {m["method"]: m for m in d["summaries"] if m.get("method") != "baseline"}
    order = [("webauthn", "PoIA (WebAuthn)"), ("zt_authenticator", "PoIA (ZT-Authenticator)")]

    print("=" * 74)
    print("tab:latency  (seconds)")
    print("=" * 74)
    warn = []
    for key, label in order:
        m = by.get(key)
        if not m or not m.get("n"):
            print(f"  {label}: NO DATA"); warn.append(f"{label}: no approvals captured"); continue
        n = int(m["n"])
        med, p95 = m["median_ms"] / 1000.0, m["p95_ms"] / 1000.0
        if n >= MIN_N_FOR_P99:
            p99 = f"{m['p99_ms'] / 1000.0:.2f}"
        else:
            p99 = "n/a"
            warn.append(f"{label}: n={n} < {MIN_N_FOR_P99}, P99 not estimable")
        print(f"{label} & {med:.2f} & {p95:.2f} & {p99} \\\\    % n={n}")

    used = d.get("approval_rows_used", {})
    inval = d.get("invalid_timing_rows", {})
    tm = d.get("test_mode_approved_rows", 0)
    counts = dict(d.get("method_counts", {}))
    wa_elig = used.get("webauthn", 0) - inval.get("webauthn", 0)
    zt_elig = used.get("zt_authenticator", 0) - inval.get("zt_authenticator", 0)

    print()
    print("=" * 74)
    print("line 933 prose")
    print("=" * 74)
    print(f"Live approvals were collected for both signing backends: {wa_elig} WebAuthn and "
          f"{zt_elig} ZT-Authenticator approvals, each measured from server-side intent "
          f"creation to the server-recorded approval event.")

    print()
    print("=" * 74)
    print("line 1007 eligible-sample and exclusion accounting")
    print("=" * 74)
    print(f"Of {used.get('webauthn',0)} recorded WebAuthn approvals and "
          f"{used.get('zt_authenticator',0)} recorded ZT-Authenticator approvals, "
          f"{inval.get('webauthn',0)} and {inval.get('zt_authenticator',0)} respectively were "
          f"excluded for missing timing, leaving {wa_elig} and {zt_elig} eligible observations. "
          f"Denials, technical failures, and expirations are recorded as separate outcomes and "
          f"are not counted as approvals"
          + (f", and {tm} test-mode approvals were excluded as non-live." if tm else "."))

    if warn:
        print()
        print("!" * 74)
        for w in warn:
            print("!  " + w)
        print("!  If P99 is not estimable, drop that column rather than reporting the maximum.")
        print("!" * 74)

    if not a.no_figure:
        try:
            import matplotlib; matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ModuleNotFoundError:
            print("\n[figure skipped: matplotlib not installed here]")
            print("[the numbers above are complete; the figure can be rendered elsewhere]")
            return 0
        labels, vals = ["Baseline\nsession check"], [a.baseline_ms]
        for key, label in order:
            if by.get(key, {}).get("n"):
                labels.append(label.replace("PoIA (", "PoIA\n").replace(")", ""))
                vals.append(by[key]["median_ms"])
        plt.rcParams.update({"font.size": 7, "font.family": "serif", "axes.linewidth": 0.6})
        fig, ax = plt.subplots(figsize=(3.4, 2.2))
        ax.set_axisbelow(True)  # grid behind bars
        colors = ["#6b6b6b", "#1f4e79", "#a8460f"][: len(vals)]
        bars = ax.bar(range(len(vals)), vals, color=colors, width=0.6)
        ax.set_yscale("log"); ax.set_ylabel("Median latency (ms, log scale)")
        ax.set_xticks(range(len(vals))); ax.set_xticklabels(labels)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v * 1.35,
                    (f"{v:.3f} ms" if v < 1 else f"{v/1000:.2f} s"), ha="center", fontsize=6)
        ax.set_ylim(a.baseline_ms / 3, max(vals) * 8)
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
        ax.grid(axis="y", alpha=0.25, lw=0.4, which="both")
        a.figure_out.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(a.figure_out, bbox_inches="tight", pad_inches=0.02)
        print(f"\nfigure written: {a.figure_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
