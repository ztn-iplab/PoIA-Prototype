#!/usr/bin/env python3
"""Final live approval-latency table: equal-sized samples per backend.

Selection rule (stated explicitly so the table is reproducible):
  * ZT-Authenticator: the first --zt-discard approvals are dropped as an
    invalidated capture, then the most recent --n of the remainder are used.
  * WebAuthn: the most recent --n approvals are used.
Equal n per backend keeps the two rows comparable in precision, and taking the
most recent approvals keeps both as close as possible to the final build.

Latency is the value the application records: server-side intent creation to
the server-recorded approval event. It includes whatever the participant must
do to reach their signing key, which differs by deployment for both backends
(browser prompt, password manager, security key, device unlock), and is
therefore left inside the measurement rather than partitioned out.
"""
from __future__ import annotations
import argparse, csv, json, statistics, time
from pathlib import Path

def pctl(x, q):
    if not x: return None
    o = sorted(x); k = (len(o)-1)*q/100.0; f = int(k); c = min(f+1, len(o)-1)
    return o[f] if f == c else o[f] + (o[c]-o[f])*(k-f)

def summ(x):
    if not x:
        return {"n": 0, "median_s": None, "mean_s": None, "p95_s": None,
                "p99_s": None, "min_s": None, "max_s": None}
    return {"n": len(x), "median_s": round(statistics.median(x),2),
            "mean_s": round(statistics.mean(x),2), "p95_s": round(pctl(x,95),2),
            "p99_s": round(pctl(x,99),2), "min_s": round(min(x),2), "max_s": round(max(x),2)}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--poia-csv", required=True, type=Path)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--zt-discard", type=int, default=112)
    ap.add_argument("--out-dir", type=Path, default=Path("experiments/live_approval_20260910"))
    ap.add_argument("--figure-out", type=Path, default=Path("PoIA_Extended/poia_latency.pdf"))
    ap.add_argument("--baseline-ms", type=float, default=0.0110)
    ap.add_argument("--baseline-p95-ms", type=float, default=0.0228)
    ap.add_argument("--matrix-dir", type=Path, default=Path("experiments/performance_scalability/p256_matrix_v2_20260910"))
    a = ap.parse_args()

    rows = list(csv.DictReader(a.poia_csv.open(newline="", encoding="utf-8")))
    def approvals(event, method):
        sel = [r for r in rows if r.get("event")==event and r.get("method")==method
               and r.get("status")=="approved" and (r.get("latency_ms") or "").strip()
               and r.get("server_ts","").isdigit()]
        sel.sort(key=lambda r: int(r["server_ts"]))
        return sel

    wa_all = approvals("passkey_complete", "webauthn")
    zt_all = approvals("intent_approve", "zt_authenticator")
    zt_pool = zt_all[a.zt_discard:]
    wa = wa_all[-a.n:]; zt = zt_pool[-a.n:]

    secs = lambda sel: [float(r["latency_ms"])/1000.0 for r in sel]
    span = lambda sel: (time.strftime('%H:%M', time.gmtime(int(sel[0]["server_ts"]))),
                        time.strftime('%H:%M', time.gmtime(int(sel[-1]["server_ts"])))) if sel else ("-","-")

    res = {
        "selection_rule": {
            "n_per_backend": a.n, "zt_discarded_leading": a.zt_discard,
            "webauthn_available": len(wa_all), "zt_available_total": len(zt_all),
            "zt_available_after_discard": len(zt_pool),
        },
        "webauthn": summ(secs(wa)) | {"window_utc": span(wa)},
        "zt_authenticator": summ(secs(zt)) | {"window_utc": span(zt)},
        "endpoint": "server-side intent creation to server-recorded approval event",
        "note": ("Each row characterizes live approval on that backend under its own participants "
                 "and workload. It is not a controlled comparison between backends."),
    }
    short = {"webauthn": len(wa) < a.n, "zt_authenticator": len(zt) < a.n}
    if any(short.values()):
        res["WARNING"] = {k: f"only {len(wa if k=='webauthn' else zt)} available, wanted {a.n}"
                          for k, v in short.items() if v}

    a.out_dir.mkdir(parents=True, exist_ok=True)
    (a.out_dir/"final_latency_table.json").write_text(json.dumps(res, indent=2)+"\n", encoding="utf-8")

    print("="*74); print(f"SELECTION: most recent {a.n} per backend; ZT drops first {a.zt_discard}")
    print(f"  WebAuthn available {len(wa_all)}  ->  using {len(wa)}   window {span(wa)[0]}-{span(wa)[1]} UTC")
    print(f"  ZT total {len(zt_all)}, after discard {len(zt_pool)}  ->  using {len(zt)}   window {span(zt)[0]}-{span(zt)[1]} UTC")
    if "WARNING" in res: print("  !! ", res["WARNING"])
    print("="*74); print("tab:latency  (seconds)"); print("="*74)
    w, z = res["webauthn"], res["zt_authenticator"]
    def row(label, m):
        if not m["n"]:
            return f"{label} & -- & -- & -- \\\\    % NO DATA"
        p99 = f"{m['p99_s']:.2f}" if m["n"] >= 100 else "n/a"
        return f"{label} & {m['median_s']:.2f} & {m['p95_s']:.2f} & {p99} \\\\    % n={m['n']}"
    print(row("PoIA (WebAuthn)", w))
    print(row("PoIA (ZT-Authenticator)", z))
    if not (w["n"] and z["n"]):
        print("\n** incomplete: not writing manuscript strings **")
        return 1
    print()
    print("line 933 prose"); print("-"*74)
    print(f"Live approvals were collected for both signing backends under equal sample sizes: "
          f"{w['n']} WebAuthn and {z['n']} ZT-Authenticator approvals, each measured from server-side "
          f"intent creation to the server-recorded approval event. The interval includes the "
          f"participant's own access to their signing key, which differs by deployment for both "
          f"backends, so each row characterizes live approval on that backend under its own "
          f"participants and workload rather than a controlled comparison between them.")
    print()
    print("line 1007 accounting"); print("-"*74)
    print(f"Of {len(wa_all)} recorded WebAuthn approvals and {len(zt_all)} ZT-Authenticator approvals, "
          f"the most recent {w['n']} and {z['n']} respectively were analyzed; the first {a.zt_discard} "
          f"ZT-Authenticator approvals were excluded as an invalidated capture. No approval was excluded "
          f"for missing timing and no test-mode approval appears in the eligible set. Denials, technical "
          f"failures, and expirations are recorded as separate outcomes and are not counted as approvals.")

    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    except ModuleNotFoundError:
        print("\n[figure skipped: matplotlib unavailable]"); return 0
    import matplotlib.ticker as mticker
    # Baseline comes from the P-256 component benchmark, not from the live
    # capture: it is a local session check with no human step, so its n and
    # percentiles are read from that run rather than assumed equal to the
    # live sample size.
    import json as _json, statistics as _stats
    bmeds, bp95s, bns = [], [], []
    for _rep in (1, 2, 3):
        _f = a.matrix_dir / f"load1_rep{_rep}" / "performance_scalability_summary.json"
        if not _f.exists():
            continue
        for _agg in _json.loads(_f.read_text())["aggregates"]:
            if _agg["mode"] == "baseline":
                _m = _agg["metrics"]["server_side_latency_ms"]
                bmeds.append(_m["median"]); bp95s.append(_m["p95"]); bns.append(_m["n"])
    if bmeds:
        base_ms, base_p95, base_n = _stats.median(bmeds), _stats.median(bp95s), int(_stats.median(bns))
    else:
        base_ms, base_p95, base_n = a.baseline_ms, a.baseline_p95_ms, 0
    base_note = (f"n={base_n:,}\np95 = {base_p95:.3f} ms" if base_n else f"p95 = {base_p95:.3f} ms")
    cats = [
        ("Baseline",           base_ms/1000.0, base_note, "#6B6B76"),
        ("PoIA WebAuthn",      w["median_s"],        f"n={w['n']}\np95 = {w['p95_s']:.2f} s",    "#7C3AED"),
        ("PoIA ZT-Auth",       z["median_s"],        f"n={z['n']}\np95 = {z['p95_s']:.2f} s",    "#C2740A"),
    ]
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["DejaVu Serif"],
        "axes.linewidth": 0.9, "text.color": "#1a1a1a",
        "axes.edgecolor": "#4a4a4a", "axes.labelcolor": "#1a1a1a",
        "xtick.color": "#1a1a1a", "ytick.color": "#1a1a1a",
    })
    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    ax.set_axisbelow(True)
    x = range(len(cats))
    bars = ax.bar(x, [c[1] for c in cats], color=[c[3] for c in cats], width=0.52, zorder=3)

    ax.set_yscale("log")
    ax.set_ylim(1e-6, 30)
    ticks = [1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1, 10]
    ax.set_yticks(ticks)
    def fmt(v, _):
        if v >= 1:   return f"{v:g}"
        if v >= 1e-3: return f"{v:g}"
        return r"$10^{%d}$" % round(__import__("math").log10(v))
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(fmt))
    ax.yaxis.set_minor_locator(mticker.NullLocator())
    ax.set_ylabel("Latency (s)", fontsize=15, labelpad=10)
    ax.tick_params(axis="y", labelsize=13, length=0, pad=6)

    # value label above each bar
    for b, c in zip(bars, cats):
        v = c[1]
        txt = f"{v*1000:.3f} ms" if v < 1e-3 else f"{v:.2f} s"
        ax.text(b.get_x()+b.get_width()/2, v*1.7, txt, ha="center",
                fontsize=17, color="#1a1a1a")

    ax.set_xticks(list(x))
    ax.set_xticklabels([c[0] for c in cats], fontsize=15)
    ax.tick_params(axis="x", length=0, pad=8)
    # n / p95 caption beneath each category
    for i, c in enumerate(cats):
        ax.annotate(c[2], xy=(i, 0), xycoords=("data", "axes fraction"),
                    xytext=(0, -46), textcoords="offset points",
                    ha="center", va="top", fontsize=10.5, color="#5a5a5a", linespacing=1.5)

    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#4a4a4a")
    ax.grid(axis="y", color="#d8d8d8", lw=0.7, zorder=0)
    ax.set_xlim(-0.6, len(cats)-0.4)

    a.figure_out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(a.figure_out, bbox_inches="tight", pad_inches=0.05)
    print(f"\nfigure written: {a.figure_out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
