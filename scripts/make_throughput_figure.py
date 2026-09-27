#!/usr/bin/env python3
"""fig:throughput-summary -- verification latency under concurrency.

Shows what Table~\\ref{tab:load-results} cannot convey at a glance: median
verification cost stays effectively flat as concurrency rises two orders of
magnitude, while the 99th percentile grows by roughly the same factor. The
throughput column is left to the table, which carries it precisely; re-plotting
a near-constant series would spend half a figure saying "flat".

Reads the same P-256 matrix that populates the table, so figure and table
cannot drift apart.
"""
from __future__ import annotations
import argparse, json, statistics
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

ENC = {"poia_webauthn": ("WebAuthn", "#7C3AED"),
       "poia_zt_authenticator": ("ZT-Auth", "#C2740A")}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-dir", type=Path,
                    default=Path("experiments/performance_scalability/p256_matrix_v2_20260910"))
    ap.add_argument("--loads", default="1,10,80,120,200")
    ap.add_argument("--out", type=Path, default=Path("PoIA_Extended/verification_throughput.pdf"))
    a = ap.parse_args()
    loads = [int(v) for v in a.loads.split(",")]

    data = {}
    for load in loads:
        for rep in (1, 2, 3):
            f = a.matrix_dir / f"load{load}_rep{rep}" / "performance_scalability_summary.json"
            if not f.exists(): continue
            for agg in json.loads(f.read_text())["aggregates"]:
                if agg["mode"] in ENC:
                    data.setdefault((agg["mode"], load), []).append(agg)
    med = lambda mode, load, k: statistics.median(
        [r["metrics"]["verification_ms"][k] for r in data[(mode, load)]])

    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["DejaVu Serif"],
        "axes.linewidth": 0.9, "text.color": "#1a1a1a",
        "axes.edgecolor": "#4a4a4a", "axes.labelcolor": "#1a1a1a",
        "xtick.color": "#1a1a1a", "ytick.color": "#1a1a1a",
    })
    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    ax.set_axisbelow(True)
    x = list(range(len(loads)))

    ends = []
    for mode, (label, color) in ENC.items():
        for stat, style, width in (("p99", ":", 2.0), ("median", "-", 2.0)):
            y = [med(mode, l, stat) for l in loads]
            ax.plot(x, y, color=color, ls=style, lw=width, marker="o", ms=5, zorder=3)
            ends.append((y[-1], f"{label} {'P99' if stat=='p99' else 'median'}"))

    ax.set_yscale("log")
    ax.set_ylabel("Verification latency (ms)", fontsize=15, labelpad=10)
    ax.set_xlabel("Concurrent workers", fontsize=15, labelpad=10)
    ax.set_xticks(x); ax.set_xticklabels([str(l) for l in loads], fontsize=13)
    ax.tick_params(axis="both", labelsize=13, length=0, pad=7)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v:g}" if v >= 0.1 else f"{v:g}"))
    ax.set_xlim(-0.25, len(loads) - 1 + 1.15)   # room for end labels

    for yv, text in ends:
        ax.annotate(text, xy=(len(loads)-1, yv), xytext=(9, 0),
                    textcoords="offset points", va="center",
                    fontsize=11.5, color="#1a1a1a")

    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#4a4a4a")
    ax.grid(axis="y", color="#d8d8d8", lw=0.7, zorder=0)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(a.out, bbox_inches="tight", pad_inches=0.05)
    print(f"written: {a.out}")
    for l in loads:
        print(f"  conc {l:>3}: "
              f"WA med={med('poia_webauthn',l,'median'):6.3f} p99={med('poia_webauthn',l,'p99'):7.3f}   "
              f"ZT med={med('poia_zt_authenticator',l,'median'):6.3f} p99={med('poia_zt_authenticator',l,'p99'):7.3f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
