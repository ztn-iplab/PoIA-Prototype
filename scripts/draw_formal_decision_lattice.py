#!/usr/bin/env python3
"""Draw the formal PoIA decision lattice figure."""

from __future__ import annotations

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "experiments" / "manuscript_20260825" / "figures"
SVG = OUT_DIR / "fig3_formal_decision_lattice.svg"
PDF = OUT_DIR / "fig3_formal_decision_lattice.pdf"
MANUSCRIPT_SVG = ROOT / "PoIA_Extended" / "fig3_formal_decision_lattice.svg"
MANUSCRIPT_PDF = ROOT / "PoIA_Extended" / "fig3_formal_decision_lattice.pdf"


BLUE = "#2F80B7"
BLUE_DARK = "#005A8D"
BLUE_LIGHT = "#EAF5FF"
BLUE_PALE = "#F7FBFF"
GRID = "#BFD7E8"
GRAY = "#4B5563"
INK = "#000000"
TEXT = "#000000"
TEXT_MUTED = "#000000"


def rect(parts: list[str], x: float, y: float, w: float, h: float, stroke: str, fill: str = "#FFFFFF", dash: str = "") -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    parts.append(
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="8" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash_attr}/>'
    )


def text(parts: list[str], x: float, y: float, value: str, cls: str, anchor: str = "middle") -> None:
    parts.append(f'<text class="{cls}" x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}">{escape(value)}</text>')


def line(parts: list[str], x1: float, y1: float, x2: float, y2: float, color: str, dash: str = "", arrow: bool = True) -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    marker = ' marker-end="url(#arrow-blue)"' if arrow and color == BLUE_DARK else ' marker-end="url(#arrow-gray)"' if arrow else ""
    parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="2.1"{dash_attr}{marker}/>')


def polyline(parts: list[str], points: list[tuple[float, float]], color: str, arrow: bool = True) -> None:
    marker = ' marker-end="url(#arrow-blue)"' if arrow else ""
    encoded = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    parts.append(f'<polyline points="{encoded}" fill="none" stroke="{color}" stroke-width="2.1"{marker}/>')


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    width = 1420
    height = 760
    node_w = 208
    node_h = 96
    top_y = 72
    centers = [160, 435, 710, 985, 1260]
    predicates = [
        ("D_authn", "principal-session", "binding"),
        ("D_policy", "ordinary authorization", "policy"),
        ("D_intent", "valid proof and", "semantic match"),
        ("D_fresh", "nonce and validity", "interval"),
        ("D_context", "RP, tenant, channel", "constraints"),
    ]

    join_x = 204
    join_y = 250
    join_w = 1012
    join_h = 54
    decision_x = 430
    decision_y = 374
    decision_w = 560
    decision_h = 126
    decision_cx = decision_x + decision_w / 2

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<defs>'
        '<marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#005A8D"/></marker>'
        '<marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#4B5563"/></marker>'
        '</defs>',
        '<style>'
        f'text{{font-family:Arial,Helvetica,sans-serif;fill:{TEXT}}}'
        '.pred{font-size:23px;font-weight:900}'
        f'.sub{{font-size:17px;fill:{TEXT_MUTED};font-weight:800}}'
        '.decision{font-size:25px;font-weight:900}'
        f'.formula{{font-size:21px;fill:{TEXT};font-weight:800}}'
        '.outcome{font-size:24px;font-weight:900}'
        f'.small{{font-size:18px;fill:{TEXT_MUTED};font-weight:800}}'
        '.tag{font-size:17px;font-weight:900;fill:#005A8D}'
        '.join{font-size:22px;font-weight:900;fill:#005A8D}'
        '</style>',
    ]

    # Predicate layer.
    for index, (center, (name, line1, line2)) in enumerate(zip(centers, predicates)):
        x = center - node_w / 2
        rect(parts, x, top_y, node_w, node_h, BLUE_DARK)
        text(parts, center, top_y + 33, name, "pred")
        text(parts, center, top_y + 58, line1, "sub")
        text(parts, center, top_y + 78, line2, "sub")
        if index == 0:
            polyline(parts, [(center, top_y + node_h), (center, join_y - 34), (join_x + 28, join_y - 34), (join_x + 28, join_y)], BLUE_DARK)
        elif index == len(predicates) - 1:
            polyline(parts, [(center, top_y + node_h), (center, join_y - 34), (join_x + join_w - 28, join_y - 34), (join_x + join_w - 28, join_y)], BLUE_DARK)
        else:
            line(parts, center, top_y + node_h, center, join_y, BLUE_DARK)

    # Conjunction layer.
    rect(parts, join_x, join_y, join_w, join_h, BLUE_DARK)
    text(parts, join_x + join_w / 2, join_y + 35, "All decision predicates must hold", "join")
    line(parts, join_x + join_w / 2, join_y + join_h, decision_cx, decision_y, BLUE_DARK)

    # Decision node.
    rect(parts, decision_x, decision_y, decision_w, decision_h, BLUE_DARK, "#FFFFFF")
    text(parts, decision_cx, decision_y + 38, "PoIA decision", "decision")
    text(parts, decision_cx, decision_y + 73, "D = D_authn ∧ D_policy ∧ D_intent", "formula")
    text(parts, decision_cx, decision_y + 100, "∧ D_fresh ∧ D_context", "formula")

    # Diagnostic side output.
    diag_x = 1060
    diag_y = 386
    diag_w = 270
    diag_h = 100
    line(parts, decision_x + decision_w, decision_y + decision_h / 2, diag_x, diag_y + diag_h / 2, GRAY, dash="7 7")
    rect(parts, diag_x, diag_y, diag_w, diag_h, GRAY)
    text(parts, diag_x + diag_w / 2, diag_y + 34, "Diagnostic value", "outcome")
    text(parts, diag_x + diag_w / 2, diag_y + 61, "failed predicate remains", "small")
    text(parts, diag_x + diag_w / 2, diag_y + 82, "distinguishable", "small")

    # Outcomes.
    accept_x = 358
    reject_x = 748
    out_y = 598
    out_w = 230
    out_h = 88
    line(parts, decision_cx - 74, decision_y + decision_h, accept_x + out_w / 2, out_y, BLUE_DARK)
    line(parts, decision_cx + 74, decision_y + decision_h, reject_x + out_w / 2, out_y, GRAY)
    text(parts, accept_x + out_w / 2 - 68, out_y - 26, "all predicates true", "tag")
    text(parts, reject_x + out_w / 2 + 54, out_y - 26, "otherwise", "tag")

    rect(parts, accept_x, out_y, out_w, out_h, BLUE_DARK)
    text(parts, accept_x + out_w / 2, out_y + 35, "Accept", "outcome")
    text(parts, accept_x + out_w / 2, out_y + 62, "execute action", "small")

    rect(parts, reject_x, out_y, out_w, out_h, GRAY)
    text(parts, reject_x + out_w / 2, out_y + 35, "Reject", "outcome")
    text(parts, reject_x + out_w / 2, out_y + 62, "record reason", "small")

    parts.append("</svg>\n")
    SVG.write_text("\n".join(parts), encoding="utf-8")
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(PDF), str(SVG)], check=True)
    MANUSCRIPT_SVG.write_text(SVG.read_text(encoding="utf-8"), encoding="utf-8")
    MANUSCRIPT_PDF.write_bytes(PDF.read_bytes())
    print(PDF)


if __name__ == "__main__":
    main()
