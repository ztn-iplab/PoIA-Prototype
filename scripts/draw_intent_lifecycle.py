#!/usr/bin/env python3
"""Draw the PoIA intent lifecycle figure."""

from __future__ import annotations

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "experiments" / "manuscript_20260825" / "figures"
SVG = OUT_DIR / "fig4_intent_lifecycle.svg"
PDF = OUT_DIR / "fig4_intent_lifecycle.pdf"
MANUSCRIPT_SVG = ROOT / "PoIA_Extended" / "fig4_intent_lifecycle.svg"
MANUSCRIPT_PDF = ROOT / "PoIA_Extended" / "fig4_intent_lifecycle.pdf"

BLUE = "#005A8D"
BLUE_LIGHT = "#EAF5FF"
GRID = "#BFD7E8"
GRAY = "#4B5563"
TEXT = "#000000"


def rect(parts: list[str], x: float, y: float, w: float, h: float, stroke: str = BLUE, fill: str = "#FFFFFF", dash: str = "") -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    parts.append(
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="8" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash_attr}/>'
    )


def text(parts: list[str], x: float, y: float, value: str, cls: str, anchor: str = "middle") -> None:
    parts.append(f'<text class="{cls}" x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}">{escape(value)}</text>')


def arrow(parts: list[str], x1: float, y1: float, x2: float, y2: float, color: str = BLUE, dash: str = "") -> None:
    marker = "arrow-blue" if color == BLUE else "arrow-gray"
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    parts.append(
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
        f'stroke-width="2.2" marker-end="url(#{marker})"{dash_attr}/>'
    )


def elbow(parts: list[str], points: list[tuple[float, float]], color: str = GRAY, dash: str = "6 6") -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    path = "M " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in points)
    marker = "arrow-gray" if color == GRAY else "arrow-blue"
    parts.append(
        f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.2" '
        f'marker-end="url(#{marker})"{dash_attr}/>'
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    width = 1500
    height = 560
    node_w = 170
    node_h = 112
    nodes = [
        ("Construct", ["server builds", "canonical intent"]),
        ("Render", ["user-readable fields", "from same object"]),
        ("Sign", ["proof over", "canonical hash"]),
        ("Verify", ["signature", "context", "semantics"]),
        ("Consume", ["nonce becomes", "unusable"]),
        ("Execute", ["state transition"]),
        ("Archive", ["audit evidence"]),
    ]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<defs>'
        '<marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#005A8D"/></marker>'
        '<marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#4B5563"/></marker>'
        '</defs>',
        '<style>'
        f'text{{font-family:Arial,Helvetica,sans-serif;fill:{TEXT}}}'
        '.stage{font-size:22px;font-weight:900}'
        '.sub{font-size:15px;font-weight:800}'
        '.num{font-size:16px;font-weight:900;fill:#ffffff}'
        '.risk-title{font-size:21px;font-weight:900}'
        '.risk-sub{font-size:15px;font-weight:800}'
        '.label{font-size:18px;font-weight:900;fill:#005A8D}'
        '.micro{font-size:13px;font-weight:900;fill:#005A8D;letter-spacing:.5px}'
        '.note{font-size:16px;font-weight:900;fill:#005A8D}'
        '</style>',
    ]

    # Invariant rail.
    rect(parts, 395, 42, 710, 48, stroke=GRID, fill="#FFFFFF")
    text(parts, 750, 73, "Canonical intent remains the reference object", "label")

    start_x = 56
    gap = 42
    y = 168
    centers: list[tuple[float, float]] = []
    for index, (title, lines) in enumerate(nodes):
        x = start_x + index * (node_w + gap)
        cx = x + node_w / 2
        cy = y + node_h / 2
        centers.append((cx, cy))
        rect(parts, x, y, node_w, node_h)
        parts.append(f'<circle cx="{cx:.1f}" cy="{y - 24:.1f}" r="17" fill="{BLUE}" stroke="{BLUE}" stroke-width="2"/>')
        text(parts, cx, y - 18, str(index + 1), "num")
        parts.append(f'<line x1="{cx:.1f}" y1="{y - 7:.1f}" x2="{cx:.1f}" y2="{y:.1f}" stroke="{BLUE}" stroke-width="2"/>')
        text(parts, cx, y + 36, title, "stage")
        line_y = y + 66
        for line in lines:
            text(parts, cx, line_y, line, "sub")
            line_y += 20

    for index in range(len(centers) - 1):
        sx, sy = centers[index]
        dx, dy = centers[index + 1]
        arrow(parts, sx + node_w / 2 - 3, sy, dx - node_w / 2 + 3, dy)

    # Hazard annotations are intentionally below the lifecycle path, with short non-crossing links.
    risk_w = 318
    risk_h = 104
    hazard_specs = [
        ("Display drift", "rendering not derived", "from canonical bytes", 1, 194, 398),
        ("Replay window", "proof verifies but nonce", "is not consumed", 4, 735, 398),
        ("Audit gap", "execution not linked", "to evidence", 5, 1130, 398),
    ]
    for title, line1, line2, target, x, ry in hazard_specs:
        target_x, _target_y = centers[target]
        elbow(parts, [(target_x, y + node_h), (target_x, ry - 4)], color=GRAY, dash="6 6")
        y2 = ry
        rect(parts, x, y2, risk_w, risk_h, stroke=GRAY, fill="#FFFFFF", dash="7 6")
        text(parts, x + risk_w / 2, y2 + 36, title, "risk-title")
        text(parts, x + risk_w / 2, y2 + 68, line1, "risk-sub")
        text(parts, x + risk_w / 2, y2 + 88, line2, "risk-sub")

    parts.append("</svg>\n")
    SVG.write_text("\n".join(parts), encoding="utf-8")
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(PDF), str(SVG)], check=True)
    MANUSCRIPT_SVG.write_text(SVG.read_text(encoding="utf-8"), encoding="utf-8")
    MANUSCRIPT_PDF.write_bytes(PDF.read_bytes())
    print(PDF)


if __name__ == "__main__":
    main()
