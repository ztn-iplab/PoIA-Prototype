#!/usr/bin/env python3
"""Analyze real PoIA approval timings from a live telemetry snapshot."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


METHODS = {
    "baseline": "Baseline session authorization",
    "webauthn": "PoIA WebAuthn approval",
    "zt_authenticator": "PoIA ZT-Authenticator approval",
}


def parse_float(value: str | None) -> float | None:
    try:
        if value in (None, ""):
            return None
        parsed = float(value)
        return parsed if math.isfinite(parsed) and parsed >= 0 else None
    except ValueError:
        return None


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    low = math.floor(k)
    high = math.ceil(k)
    if low == high:
        return ordered[low]
    return ordered[low] * (high - k) + ordered[high] * (k - low)


def summarize(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean_ms": None, "median_ms": None, "p95_ms": None, "p99_ms": None, "min_ms": None, "max_ms": None}
    return {
        "n": len(values),
        "mean_ms": statistics.fmean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 95),
        "p99_ms": percentile(values, 99),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def real_approval_rows(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    return {
        "webauthn": [
            row
            for row in rows
            if row.get("event") == "passkey_complete"
            and row.get("method") == "webauthn"
            and row.get("status") == "approved"
        ],
        "zt_authenticator": [
            row
            for row in rows
            if row.get("event") == "intent_approve"
            and row.get("method") == "zt_authenticator"
            and row.get("status") == "approved"
        ],
    }


def baseline_summary(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("aggregates", []):
        if item.get("mode") == "baseline":
            metrics = item["metrics"]["end_to_end_latency_ms"]
            return {
                "method": "baseline",
                "label": METHODS["baseline"],
                "source": str(path),
                "endpoint": "separate local session-check microbenchmark",
                "n": int(metrics["n"]),
                "mean_ms": float(metrics["mean"]),
                "median_ms": float(metrics["median"]),
                "p95_ms": float(metrics["p95"]),
                "p99_ms": None,
                "min_ms": None,
                "max_ms": float(metrics["max"]),
            }
    return None


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def fmt_ms(value: float | int | None) -> str:
    if value is None:
        return "-"
    if value >= 1000:
        return f"{value / 1000:.2f}s"
    return f"{value:.3f}ms"


def write_svg(path: Path, summaries: list[dict[str, Any]]) -> None:
    width = 1100
    height = 720
    margin_left = 160
    margin_right = 70
    margin_top = 70
    margin_bottom = 150
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom

    # Plot in seconds on a log scale. A floor of 1 microsecond keeps the
    # measured baseline visible without visually equating it to zero.
    log_min = -6.0
    log_max = 1.0

    def y_for(seconds: float) -> float:
        log_value = math.log10(max(seconds, 10**log_min))
        return margin_top + ((log_max - log_value) / (log_max - log_min)) * plot_height

    colors = {
        "baseline": "#6B7280",
        "webauthn": "#7C3AED",
        "zt_authenticator": "#D97706",
    }
    tick_values = [0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1, 10]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Georgia,Times New Roman,serif;fill:#111111}.tick{font-size:23px}.axis-title{font-size:27px}.category{font-size:28px}.value{font-size:28px}.note{font-family:Arial,Helvetica,sans-serif;font-size:15px;fill:#555555}</style>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#111111" stroke-width="2.2"/>',
        f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{margin_left + plot_width}" y2="{margin_top + plot_height}" stroke="#777777" stroke-width="2.2"/>',
    ]
    for tick in tick_values:
        y = y_for(tick)
        tick_labels = {
            0.000001: "10^-6",
            0.00001: "10^-5",
            0.0001: "10^-4",
            0.001: "0.001",
            0.01: "0.01",
            0.1: "0.1",
            1: "1",
            10: "10",
        }
        label = tick_labels[tick]
        if tick >= 0.01:
            parts.append(f'<line x1="{margin_left}" y1="{y:.1f}" x2="{margin_left + plot_width}" y2="{y:.1f}" stroke="#d1d1d1" stroke-width="1"/>')
        parts.append(f'<text class="tick" x="{margin_left - 18}" y="{y + 8:.1f}" text-anchor="end">{escape(label)}</text>')
    parts.append(f'<text class="axis-title" transform="translate(32 {margin_top + plot_height / 2:.1f}) rotate(-90)" text-anchor="middle">Latency (s)</text>')

    bar_width = 180
    group_gap = (plot_width - (bar_width * len(summaries))) / (len(summaries) + 1)
    for index, item in enumerate(summaries):
        key = item["method"]
        seconds = float(item["median_ms"]) / 1000.0
        x = margin_left + group_gap + index * (bar_width + group_gap)
        y = y_for(seconds)
        h = margin_top + plot_height - y
        label = "Baseline" if key == "baseline" else "PoIA WebAuthn" if key == "webauthn" else "PoIA ZT-Auth"
        value_label = f"{seconds:.2f} s" if seconds >= 1 else f"{seconds * 1000:.3f} ms"
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width}" height="{h:.1f}" fill="{colors.get(key, "#333333")}"/>')
        parts.append(f'<text class="value" x="{x + bar_width / 2:.1f}" y="{max(y - 18, margin_top - 12):.1f}" text-anchor="middle">{escape(value_label)}</text>')
        parts.append(f'<text class="category" x="{x + bar_width / 2:.1f}" y="{margin_top + plot_height + 48}" text-anchor="middle">{escape(label)}</text>')
        parts.append(f'<text class="note" x="{x + bar_width / 2:.1f}" y="{margin_top + plot_height + 78}" text-anchor="middle">n={int(item["n"])}, p95={escape(fmt_ms(item.get("p95_ms")))}</text>')

    parts.append("</svg>\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts), encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--poia-csv", required=True, type=Path)
    parser.add_argument("--baseline-json", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--pdf", action="store_true", help="Also render the SVG chart to PDF with rsvg-convert.")
    parser.add_argument("--no-figure", action="store_true", help="Update numeric summaries without changing existing figures.")
    args = parser.parse_args()

    rows = load_rows(args.poia_csv)
    approval_sets = real_approval_rows(rows)

    method_rows: list[dict[str, Any]] = []
    action_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []

    baseline = baseline_summary(args.baseline_json)
    if baseline:
        summaries.append(baseline)
        method_rows.append(baseline)

    for method, selected in approval_sets.items():
        latencies = [lat for lat in (parse_float(row.get("latency_ms")) for row in selected) if lat is not None]
        summary = summarize(latencies)
        item = {
            "method": method,
            "label": METHODS[method],
            "source": str(args.poia_csv),
            "endpoint": "server intent creation to recorded approval; protected execution excluded",
            **summary,
        }
        summaries.append(item)
        method_rows.append(item)

        by_action: dict[str, list[float]] = defaultdict(list)
        for row in selected:
            latency = parse_float(row.get("latency_ms"))
            if latency is not None:
                by_action[row.get("action") or "(missing)"].append(latency)
        for action, values in sorted(by_action.items()):
            action_rows.append({"method": method, "action": action, **summarize(values)})

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "approval_latency_by_method.csv", method_rows)
    write_csv(args.out_dir / "approval_latency_by_action.csv", action_rows)

    aggregate = {
        "evidence_class": "successful live approval intervals; not isolated signing or execution latency",
        "baseline_comparability": "different endpoint; no end-to-end overhead ratio is estimated",
        "source_csv": str(args.poia_csv),
        "source_csv_sha256": sha256(args.poia_csv),
        "total_rows": len(rows),
        "event_counts": Counter(row.get("event", "") for row in rows),
        "method_counts": Counter(row.get("method", "") for row in rows),
        "approval_rows_used": {method: len(selected) for method, selected in approval_sets.items()},
        "invalid_timing_rows": {method: sum(parse_float(row.get("latency_ms")) is None for row in selected)
                                for method, selected in approval_sets.items()},
        "test_mode_approved_rows": sum(1 for row in rows if row.get("method") == "test_mode" and row.get("status") == "approved"),
        "summaries": method_rows,
        "actions": action_rows,
    }
    (args.out_dir / "approval_latency_summary.json").write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    svg_path = args.out_dir / "approval_latency_barchart.svg"
    if not args.no_figure:
        write_svg(svg_path, summaries)
    if args.pdf and not args.no_figure:
        subprocess.run(
            ["rsvg-convert", "-f", "pdf", "-o", str(args.out_dir / "approval_latency_barchart.pdf"), str(svg_path)],
            check=True,
        )

    print(json.dumps(aggregate, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
