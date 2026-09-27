#!/usr/bin/env python3
"""Draw the authentication-vs-intent-integrity concept figure."""

from __future__ import annotations

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "experiments" / "manuscript_20260825" / "figures"
SVG = OUT_DIR / "fig1_authorization_semantic_gap.svg"
PDF = OUT_DIR / "fig1_authorization_semantic_gap.pdf"
MANUSCRIPT_SVG = ROOT / "PoIA_Extended" / "fig1_authorization_semantic_gap.svg"
MANUSCRIPT_PDF = ROOT / "PoIA_Extended" / "fig1_authorization_semantic_gap.pdf"


BLUE = "#2F80B7"
BLUE_DARK = "#1F5F8B"
BLUE_LIGHT = "#EAF5FF"
BLUE_PALE = "#F7FBFF"
GRID = "#BFD7E8"
INK = "#15191D"
MUTED = "#425466"
REJECT = "#7F8FA3"


def rect(parts: list[str], x: float, y: float, w: float, h: float, fill: str, stroke: str, dash: str = "") -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    parts.append(
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="8" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="2"{dash_attr}/>'
    )


def text(parts: list[str], x: float, y: float, value: str, cls: str, anchor: str = "middle") -> None:
    parts.append(f'<text class="{cls}" x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}">{escape(value)}</text>')


def arrow(parts: list[str], x1: float, y1: float, x2: float, y2: float, color: str = INK, dash: str = "") -> None:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    marker = "arrow"
    if color == BLUE_DARK:
        marker = "arrow-blue"
    elif color == REJECT:
        marker = "arrow-gray"
    parts.append(
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
        f'stroke-width="2.2" marker-end="url(#{marker})"{dash_attr}/>'
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    width = 1480
    height = 760
    panel_w = 640
    panel_h = 620
    left_x = 65
    right_x = 775
    panel_y = 65

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<defs>'
        '<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#15191D"/></marker>'
        '<marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#1F5F8B"/></marker>'
        '<marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#7F8FA3"/></marker>'
        '</defs>',
        '<style>'
        'text{font-family:Arial,Helvetica,sans-serif;fill:#15191D}'
        '.panel{font-size:27px;font-weight:800;letter-spacing:.1px;fill:#1F5F8B}'
        '.box-title{font-size:23px;font-weight:800}'
        '.body{font-size:19px;fill:#1f2933}'
        '.small{font-size:17px;fill:#425466}'
        '.callout{font-size:21px;font-weight:800}'
        '.tag{font-size:17px;font-weight:800;fill:#1f2933}'
        '</style>',
    ]

    # Panels.
    rect(parts, left_x, panel_y, panel_w, panel_h, "#FFFFFF", "#8DBEDD", "10 8")
    rect(parts, right_x, panel_y, panel_w, panel_h, "#FFFFFF", BLUE_DARK, "10 8")
    text(parts, left_x + panel_w / 2, panel_y + 48, "WITHOUT PoIA: semantic gap", "panel")
    text(parts, right_x + panel_w / 2, panel_y + 48, "WITH PoIA: intent integrity", "panel")

    # Left panel: session authorizes many actions.
    session_x = left_x + 92
    session_y = panel_y + 92
    session_w = panel_w - 184
    session_h = 104
    rect(parts, session_x, session_y, session_w, session_h, "#FFFFFF", "#8DBEDD")
    text(parts, session_x + session_w / 2, session_y + 41, "Authenticated session S", "box-title")
    text(parts, session_x + session_w / 2, session_y + 70, "cookie, bearer token, or SAML assertion", "body")

    action_y = panel_y + 330
    action_w = 168
    action_h = 102
    actions = [
        (left_x + 54, "Action A1", "Transfer $5,000"),
        (left_x + 236, "Action A2", "Grant admin role"),
        (left_x + 418, "Action A3", "Bulk export records"),
    ]
    for x, title, subtitle in actions:
        rect(parts, x, action_y, action_w, action_h, "#FFFFFF", BLUE_DARK)
        text(parts, x + action_w / 2, action_y + 40, title, "box-title")
        text(parts, x + action_w / 2, action_y + 70, subtitle, "small")
        arrow(parts, session_x + session_w / 2, session_y + session_h, x + action_w / 2, action_y, color=BLUE_DARK, dash="7 6")

    bracket_y = panel_y + 476
    parts.append(f'<line x1="{left_x + 88:.1f}" y1="{bracket_y:.1f}" x2="{left_x + panel_w - 88:.1f}" y2="{bracket_y:.1f}" stroke="{BLUE_DARK}" stroke-width="2"/>')
    parts.append(f'<line x1="{left_x + 88:.1f}" y1="{bracket_y - 10:.1f}" x2="{left_x + 88:.1f}" y2="{bracket_y + 10:.1f}" stroke="{BLUE_DARK}" stroke-width="2"/>')
    parts.append(f'<line x1="{left_x + panel_w - 88:.1f}" y1="{bracket_y - 10:.1f}" x2="{left_x + panel_w - 88:.1f}" y2="{bracket_y + 10:.1f}" stroke="{BLUE_DARK}" stroke-width="2"/>')
    text(parts, left_x + panel_w / 2, bracket_y + 44, "Session authorizes any action: no semantic check", "callout")

    rect(parts, left_x + 102, panel_y + 548, panel_w - 204, 72, "#FFFFFF", "#8DBEDD")
    text(parts, left_x + panel_w / 2, panel_y + 578, "Intent assurance: none", "box-title")
    text(parts, left_x + panel_w / 2, panel_y + 604, "Replay, relay, and substitution can pass session checks", "small")

    # Right panel: session plus PoIA gate.
    r_session_x = right_x + 92
    r_session_y = panel_y + 92
    rect(parts, r_session_x, r_session_y, session_w, session_h, "#FFFFFF", "#8DBEDD")
    text(parts, r_session_x + session_w / 2, r_session_y + 41, "Authenticated session S", "box-title")
    text(parts, r_session_x + session_w / 2, r_session_y + 70, "necessary but not sufficient", "body")

    gate_x = right_x + 72
    gate_y = panel_y + 270
    gate_w = panel_w - 144
    gate_h = 126
    arrow(parts, r_session_x + session_w / 2, r_session_y + session_h, r_session_x + session_w / 2, gate_y, color=BLUE_DARK)
    rect(parts, gate_x, gate_y, gate_w, gate_h, "#FFFFFF", BLUE_DARK)
    text(parts, gate_x + gate_w / 2, gate_y + 43, "PoIA intent gate", "box-title")
    text(parts, gate_x + gate_w / 2, gate_y + 73, "D_intent: operation, fresh nonce, signature", "body")
    text(parts, gate_x + gate_w / 2, gate_y + 100, "and matching context/semantics", "body")

    reject_x = right_x + 72
    exec_x = right_x + panel_w - 272
    decision_y = panel_y + 450
    decision_w = 224
    decision_h = 88
    arrow(parts, gate_x + 138, gate_y + gate_h, reject_x + decision_w / 2, decision_y, color=REJECT)
    arrow(parts, gate_x + gate_w - 138, gate_y + gate_h, exec_x + decision_w / 2, decision_y, color=BLUE_DARK)
    text(parts, reject_x + 42, decision_y - 26, "mismatch", "tag")
    text(parts, exec_x + decision_w - 42, decision_y - 26, "exact match", "tag")

    rect(parts, reject_x, decision_y, decision_w, decision_h, "#FFFFFF", REJECT)
    text(parts, reject_x + decision_w / 2, decision_y + 37, "Reject", "box-title")
    text(parts, reject_x + decision_w / 2, decision_y + 64, "log reason", "small")

    rect(parts, exec_x, decision_y, decision_w, decision_h, "#FFFFFF", BLUE_DARK)
    text(parts, exec_x + decision_w / 2, decision_y + 37, "Execute A", "box-title")
    text(parts, exec_x + decision_w / 2, decision_y + 64, "verified semantics", "small")

    rect(parts, right_x + 60, panel_y + 560, panel_w - 120, 46, "#FFFFFF", BLUE_DARK)
    text(parts, right_x + panel_w / 2, panel_y + 600, "Authentication proves who; PoIA proves what", "callout")

    parts.append("</svg>\n")
    SVG.write_text("\n".join(parts), encoding="utf-8")
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(PDF), str(SVG)], check=True)
    MANUSCRIPT_SVG.write_text(SVG.read_text(encoding="utf-8"), encoding="utf-8")
    MANUSCRIPT_PDF.write_bytes(PDF.read_bytes())
    print(PDF)


if __name__ == "__main__":
    main()
