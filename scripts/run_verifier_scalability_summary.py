#!/usr/bin/env python3
"""Run and plot focused verifier scalability measurements for the manuscript."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import run_track_c_performance as track_c  # noqa: E402


SERIES = {
    "poia_webauthn_p256": {
        "label": "WebAuthn backend",
        "color": "#7C3AED",
        "dash": "",
        "marker_fill": "#7C3AED",
    },
    "poia_zt_p256": {
        "label": "ZT-Authenticator backend",
        "color": "#D97706",
        "dash": "7 6",
        "marker_fill": "#ffffff",
    },
}


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except subprocess.CalledProcessError:
        return ""


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def nice_max(value: float) -> float:
    if value <= 0:
        return 1.0
    magnitude = 10 ** (len(str(int(value))) - 1)
    for step in (1, 2, 5, 10):
        candidate = step * magnitude
        if candidate >= value:
            return candidate
    return 10 * magnitude


def point_path(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def draw_panel(
    parts: list[str],
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    y_label: str,
    rows: list[dict[str, Any]],
    metric: str,
    y_max: float,
) -> None:
    concurrencies = sorted({int(row["concurrency"]) for row in rows})
    x_positions = {
        concurrency: x + (index / (len(concurrencies) - 1)) * width
        for index, concurrency in enumerate(concurrencies)
    }

    def x_for(concurrency: int) -> float:
        return x_positions[concurrency]

    def y_for(value: float) -> float:
        return y + height - (value / y_max) * height

    parts.append(f'<text class="panel-title" x="{x + width / 2:.1f}" y="{y - 34:.1f}" text-anchor="middle">{escape(title)}</text>')
    parts.append(f'<line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{y + height:.1f}" stroke="#111111" stroke-width="2"/>')
    parts.append(f'<line x1="{x:.1f}" y1="{y + height:.1f}" x2="{x + width:.1f}" y2="{y + height:.1f}" stroke="#777777" stroke-width="2"/>')

    for i in range(5):
        value = y_max * i / 4
        yy = y_for(value)
        parts.append(f'<line x1="{x:.1f}" y1="{yy:.1f}" x2="{x + width:.1f}" y2="{yy:.1f}" stroke="#d7d7d7" stroke-width="1"/>')
        label = f"{value:.0f}" if y_max >= 100 else f"{value:.2f}".rstrip("0").rstrip(".")
        parts.append(f'<text class="tick" x="{x - 12:.1f}" y="{yy + 6:.1f}" text-anchor="end">{label}</text>')

    for concurrency in concurrencies:
        xx = x_for(concurrency)
        parts.append(f'<text class="tick" x="{xx:.1f}" y="{y + height + 32:.1f}" text-anchor="middle">{concurrency}</text>')

    parts.append(f'<text class="axis-label" x="{x + width / 2:.1f}" y="{y + height + 72:.1f}" text-anchor="middle">Concurrent requests</text>')
    parts.append(f'<text class="axis-label" transform="translate({x - 76:.1f} {y + height / 2:.1f}) rotate(-90)" text-anchor="middle">{escape(y_label)}</text>')

    for config, style in SERIES.items():
        selected = [row for row in rows if row["configuration"] == config]
        selected.sort(key=lambda row: int(row["concurrency"]))
        points = [(x_for(int(row["concurrency"])), y_for(float(row[metric]))) for row in selected]
        dash = f' stroke-dasharray="{style["dash"]}"' if style["dash"] else ""
        parts.append(f'<polyline points="{point_path(points)}" fill="none" stroke="{style["color"]}" stroke-width="4"{dash}/>')
        for xx, yy in points:
            parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="6" fill="{style["marker_fill"]}" stroke="{style["color"]}" stroke-width="3"/>')


def draw_svg(path: Path, rows: list[dict[str, Any]]) -> None:
    width = 1320
    height = 720
    panel_y = 120
    panel_w = 470
    panel_h = 390
    left_x = 145
    right_x = 770
    throughput_max = nice_max(max(float(row["throughput_decisions_per_second"]) for row in rows) * 1.08)
    latency_max = nice_max(max(float(row["p95_latency_ms"]) for row in rows) * 1.15)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Arial,Helvetica,sans-serif;fill:#111111}.panel-title{font-size:28px;font-weight:700}.tick{font-size:18px}.axis-label{font-size:22px;font-weight:700}.legend{font-size:22px;font-weight:700}</style>',
    ]
    draw_panel(parts, left_x, panel_y, panel_w, panel_h, "Throughput", "decisions/s", rows, "throughput_decisions_per_second", throughput_max)
    draw_panel(parts, right_x, panel_y, panel_w, panel_h, "P95 latency", "ms", rows, "p95_latency_ms", latency_max)

    legend_y = 618
    legend_x = 430
    for index, (config, style) in enumerate(SERIES.items()):
        y = legend_y + index * 42
        dash = f' stroke-dasharray="{style["dash"]}"' if style["dash"] else ""
        parts.append(f'<line x1="{legend_x:.1f}" y1="{y:.1f}" x2="{legend_x + 78:.1f}" y2="{y:.1f}" stroke="{style["color"]}" stroke-width="4"{dash}/>')
        parts.append(f'<circle cx="{legend_x + 39:.1f}" cy="{y:.1f}" r="6" fill="{style["marker_fill"]}" stroke="{style["color"]}" stroke-width="3"/>')
        parts.append(f'<text class="legend" x="{legend_x + 112:.1f}" y="{y + 8:.1f}">{escape(style["label"])}</text>')

    parts.append("</svg>\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--concurrency", default="1,5,10,20,40,80,120,160,200")
    parser.add_argument("--operations", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--out-dir", default="experiments/manuscript_20260825/verifier_scalability_20260825")
    parser.add_argument("--pdf", action="store_true")
    args = parser.parse_args()

    out_dir = ROOT / args.out_dir
    raw_dir = out_dir / "raw"
    derived_dir = out_dir / "derived"
    concurrencies = [int(value) for value in args.concurrency.split(",") if value.strip()]
    keys = {configuration: track_c.generate_key() for configuration in SERIES}
    repeat_rows: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="poia-verifier-scalability-") as temp:
        temp_dir = Path(temp)
        for configuration in SERIES:
            for concurrency in concurrencies:
                for repeat in range(1, args.repeats + 1):
                    cell, rows = track_c.run_throughput_cell(
                        configuration=configuration,
                        nonce_backend="memory",
                        workload="accept",
                        concurrency=concurrency,
                        operations=args.operations,
                        key=keys[configuration],
                        temp_dir=temp_dir,
                    )
                    write_csv(raw_dir / f"{cell['cell_id']}-repeat-{repeat}.csv", rows)
                    repeat_rows.append(
                        {
                            "configuration": configuration,
                            "label": SERIES[configuration]["label"],
                            "repeat": repeat,
                            "nonce_backend": cell["nonce_backend"],
                            "workload": cell["workload"],
                            "concurrency": cell["concurrency"],
                            "operations": cell["operations"],
                            "throughput_decisions_per_second": cell["throughput_decisions_per_second"],
                            "median_latency_ms": cell["latency"]["median_ms"],
                            "p95_latency_ms": cell["latency"]["p95_ms"],
                            "p99_latency_ms": cell["latency"]["p99_ms"],
                            "incorrect_accepts": cell["incorrect_accepts"],
                            "incorrect_rejects": cell["incorrect_rejects"],
                        }
                    )

    summary_rows: list[dict[str, Any]] = []
    for configuration in SERIES:
        for concurrency in concurrencies:
            selected = [row for row in repeat_rows if row["configuration"] == configuration and row["concurrency"] == concurrency]
            summary_rows.append(
                {
                    "configuration": configuration,
                    "label": SERIES[configuration]["label"],
                    "nonce_backend": "memory",
                    "workload": "accept",
                    "concurrency": concurrency,
                    "operations_per_repeat": args.operations,
                    "repeats": args.repeats,
                    "throughput_decisions_per_second": statistics.median(float(row["throughput_decisions_per_second"]) for row in selected),
                    "median_latency_ms": statistics.median(float(row["median_latency_ms"]) for row in selected),
                    "p95_latency_ms": statistics.median(float(row["p95_latency_ms"]) for row in selected),
                    "p99_latency_ms": statistics.median(float(row["p99_latency_ms"]) for row in selected),
                    "incorrect_accepts": sum(int(row["incorrect_accepts"]) for row in selected),
                    "incorrect_rejects": sum(int(row["incorrect_rejects"]) for row in selected),
                }
            )

    manifest = {
        "run_id": args.run_id,
        "experiment": "verifier_scalability_summary",
        "repository_commit": git("rev-parse", "HEAD"),
        "git_status_entries": len([line for line in git("status", "--porcelain").splitlines() if line]),
        "runner_sha256": track_c.sha256_file(Path(__file__)),
        "track_c_runner_sha256": track_c.sha256_file(ROOT / "scripts" / "run_track_c_performance.py"),
        "concurrency": concurrencies,
        "operations_per_cell": args.operations,
        "repeats_per_cell": args.repeats,
        "configurations": list(SERIES),
        "nonce_backend": "memory",
        "workload": "accept",
        "approval_time": "excluded",
    }
    write_json(out_dir / "manifest.json", manifest)
    write_csv(derived_dir / "verifier_scalability_repeats.csv", repeat_rows)
    write_csv(derived_dir / "verifier_scalability_summary.csv", summary_rows)
    write_json(derived_dir / "verifier_scalability_summary.json", {"manifest": manifest, "rows": summary_rows, "repeat_rows": repeat_rows})

    svg_path = derived_dir / "verifier_scalability_summary.svg"
    draw_svg(svg_path, summary_rows)
    if args.pdf:
        subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(derived_dir / "verifier_scalability_summary.pdf"), str(svg_path)], check=True)

    print(json.dumps({"run_id": args.run_id, "rows": len(summary_rows), "out_dir": str(out_dir)}, indent=2))


if __name__ == "__main__":
    main()
