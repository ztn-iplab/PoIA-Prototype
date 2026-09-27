#!/usr/bin/env python3
"""Draw a publication-style threat/invariant coverage matrix."""

from __future__ import annotations

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "experiments" / "manuscript_20260825" / "figures"
SVG = OUT_DIR / "fig2_threat_surface_matrix.svg"
PDF = OUT_DIR / "fig2_threat_surface_matrix.pdf"
MANUSCRIPT_SVG = ROOT / "PoIA_Extended" / "fig2_threat_surface_matrix.svg"
MANUSCRIPT_PDF = ROOT / "PoIA_Extended" / "fig2_threat_surface_matrix.pdf"

ROWS = [
    "Session hijacking",
    "Replay",
    "Relay phishing",
    "Request tampering",
    "Token reuse",
    "Confused deputy",
    "Multi-step abuse",
]

COLUMNS = [
    ("Fresh proof", "missing proof"),
    ("Nonce state", "reused nonce"),
    ("Context", "wrong RP/workflow"),
    ("Semantic match", "changed fields"),
    ("Audit trail", "reason code"),
]

COVERAGE = [
    [1, 0, 0, 0, 1],
    [0, 1, 0, 0, 1],
    [1, 0, 1, 0, 1],
    [0, 0, 0, 1, 1],
    [1, 0, 0, 1, 1],
    [1, 0, 1, 1, 1],
    [1, 1, 1, 1, 1],
]


def text(parts: list[str], x: float, y: float, value: str, cls: str, anchor: str = "middle") -> None:
    parts.append(f'<text class="{cls}" x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}">{escape(value)}</text>')


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    width = 1320
    height = 690
    left = 292
    top = 144
    cell_w = 176
    row_h = 66
    header_h = 92
    row_label_w = 256
    matrix_w = cell_w * len(COLUMNS)
    matrix_h = row_h * len(ROWS)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>'
        'text{font-family:Arial,Helvetica,sans-serif;fill:#15191d}'
        '.head{font-size:21px;font-weight:700}'
        '.sub{font-size:17px;fill:#4d6475}'
        '.row{font-size:21px;font-weight:700}'
        '.legend{font-size:18px;fill:#3f3f46}'
        '</style>',
        f'<rect x="{left - row_label_w:.1f}" y="{top - header_h:.1f}" width="{row_label_w:.1f}" height="{header_h:.1f}" fill="#EAF5FF" stroke="#3B82B8" stroke-width="1.7"/>',
        f'<rect x="{left:.1f}" y="{top - header_h:.1f}" width="{matrix_w:.1f}" height="{header_h:.1f}" fill="#F3FAFF" stroke="#6BAED6" stroke-width="1.7"/>',
    ]

    text(parts, left - row_label_w / 2, top - 38, "Attack capability", "head")
    for index, (heading, subheading) in enumerate(COLUMNS):
        x = left + index * cell_w
        parts.append(f'<line x1="{x:.1f}" y1="{top - header_h:.1f}" x2="{x:.1f}" y2="{top + matrix_h:.1f}" stroke="#D6E7F4" stroke-width="1"/>')
        text(parts, x + cell_w / 2, top - 52, heading, "head")
        text(parts, x + cell_w / 2, top - 25, subheading, "sub")
    parts.append(f'<line x1="{left + matrix_w:.1f}" y1="{top - header_h:.1f}" x2="{left + matrix_w:.1f}" y2="{top + matrix_h:.1f}" stroke="#D6E7F4" stroke-width="1"/>')

    for row_index, row in enumerate(ROWS):
        y = top + row_index * row_h
        fill = "#ffffff" if row_index % 2 == 0 else "#F7FBFF"
        parts.append(f'<rect x="{left - row_label_w:.1f}" y="{y:.1f}" width="{row_label_w + matrix_w:.1f}" height="{row_h:.1f}" fill="{fill}"/>')
        parts.append(f'<line x1="{left - row_label_w:.1f}" y1="{y:.1f}" x2="{left + matrix_w:.1f}" y2="{y:.1f}" stroke="#DCECF7" stroke-width="1"/>')
        text(parts, left - 24, y + 42, row, "row", anchor="end")
        for col_index, covered in enumerate(COVERAGE[row_index]):
            cx = left + col_index * cell_w + cell_w / 2
            cy = y + row_h / 2 + 3
            if covered:
                parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="15" fill="#2F80B7" stroke="#1F5F8B" stroke-width="2"/>')
            else:
                parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="15" fill="#ffffff" stroke="#8FA9BA" stroke-width="2.5"/>')

    bottom = top + matrix_h
    parts.append(f'<line x1="{left - row_label_w:.1f}" y1="{bottom:.1f}" x2="{left + matrix_w:.1f}" y2="{bottom:.1f}" stroke="#BFD7E8" stroke-width="1.5"/>')
    parts.append(f'<line x1="{left - row_label_w:.1f}" y1="{top - header_h:.1f}" x2="{left - row_label_w:.1f}" y2="{bottom:.1f}" stroke="#3B82B8" stroke-width="1.5"/>')
    parts.append(f'<line x1="{left + matrix_w:.1f}" y1="{top - header_h:.1f}" x2="{left + matrix_w:.1f}" y2="{bottom:.1f}" stroke="#6BAED6" stroke-width="1.5"/>')

    legend_y = bottom + 58
    legend_x = left + 260
    parts.append(f'<circle cx="{legend_x:.1f}" cy="{legend_y:.1f}" r="12" fill="#2F80B7" stroke="#1F5F8B" stroke-width="2"/>')
    text(parts, legend_x + 26, legend_y + 7, "Primary invariant", "legend", anchor="start")
    parts.append(f'<circle cx="{legend_x + 240:.1f}" cy="{legend_y:.1f}" r="12" fill="#ffffff" stroke="#8FA9BA" stroke-width="2.3"/>')
    text(parts, legend_x + 266, legend_y + 7, "Not primary", "legend", anchor="start")

    parts.append("</svg>\n")
    SVG.write_text("\n".join(parts), encoding="utf-8")
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(PDF), str(SVG)], check=True)
    MANUSCRIPT_SVG.write_text(SVG.read_text(encoding="utf-8"), encoding="utf-8")
    MANUSCRIPT_PDF.write_bytes(PDF.read_bytes())
    print(PDF)


if __name__ == "__main__":
    main()
