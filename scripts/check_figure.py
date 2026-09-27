#!/usr/bin/env python3
"""Check an exported figure PDF against the locked spec in PoIA_Extended/FIGURE_SPEC.md."""
import re, subprocess, sys, statistics

COL, TXT, COLH = 244.0, 516.0, 666.0
BAND = {"1col": (1.4, 1.8), "2col": (2.1, 2.4)}

def main(path, kind, caption_lines=4):
    info = subprocess.run(["pdfinfo", path], capture_output=True, text=True).stdout
    w, h = (float(x) for x in re.search(r"Page size:\s+([\d.]+) x ([\d.]+)", info).groups())
    target = COL if kind == "1col" else TXT
    scale = target / w
    aspect = w / h
    out = subprocess.run(["pdftotext", "-bbox-layout", path, "-"],
                         capture_output=True, text=True).stdout
    hs = [float(m.group(4)) - float(m.group(2)) for m in re.finditer(
        r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)"', out)]
    hs = sorted(x for x in hs if 1 < x < 200)
    rendered_h = target / aspect
    cap = caption_lines * 10 + 24
    cost = (rendered_h + cap) * (1 if kind == "1col" else 2)
    lo, hi = BAND[kind]
    print(f"{path}")
    print(f"  native      {w:.0f} x {h:.0f} pt   aspect {aspect:.2f}   scale {scale:.3f}x")
    if hs:
        mn = hs[0] * scale
        p10 = hs[int(.10 * len(hs))] * scale
        print(f"  on-page text  min {mn:.1f} pt   p10 {p10:.1f} pt   median {statistics.median(hs)*scale:.1f} pt")
    else:
        mn = p10 = 0.0
        print("  on-page text  (no extractable text)")
    print(f"  page cost   {rendered_h:.0f} pt tall -> {100*cost/(2*COLH):.1f}% of a page")
    ok = True
    if hs and mn < 8.0:
        print(f"  FAIL  smallest text {mn:.1f} pt is below the 8 pt floor"); ok = False
    if not (lo <= aspect <= hi):
        print(f"  FAIL  aspect {aspect:.2f} outside the {lo}-{hi} band for {kind}"); ok = False
    print("  PASS" if ok else "  -> redraw")
    return 0 if ok else 1

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: check_figure.py <pdf> <1col|2col> [caption_lines]")
    sys.exit(main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 4))
