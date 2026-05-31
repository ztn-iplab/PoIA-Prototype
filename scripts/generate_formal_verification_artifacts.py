#!/usr/bin/env python3
"""Generate formal-verification expansion artifacts for PoIA."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List


LEMMA_MAP = [
    ("no_execution_without_matching_intent", "No execution without matching intent", "Session misuse, missing proof"),
    ("nonce_freshness", "Nonce freshness / issued intent existence", "Injected or unissued intent"),
    ("replay_resistance", "Replay resistance", "Proof replay"),
    ("intent_non_transferability", "Intent non-transferability", "Intent/scope substitution"),
    ("context_confinement", "Context confinement", "Wrong RP/session/tenant context"),
    ("session_compromise_does_not_imply_execution", "Session compromise does not imply execution", "Stolen session"),
    ("action_substitution_impossibility", "Action substitution impossibility", "Cross-action reuse"),
]


def parse_lemma_results(output: str) -> Dict[str, str]:
    results: Dict[str, str] = {}
    for lemma, _, _ in LEMMA_MAP:
        match = re.search(rf"^\s*{re.escape(lemma)}\s+\(all-traces\):\s+([^\n]+)$", output, re.MULTILINE)
        results[lemma] = match.group(1).strip() if match else "not reported"
    return results


def run_tamarin(root: Path, model: Path, out_txt: Path) -> Dict[str, Any]:
    exe = shutil.which("tamarin-prover")
    if not exe:
        return {"available": False, "returncode": None, "note": "tamarin-prover not found on PATH", "lemma_results": {}}
    rel_model = model.relative_to(root)
    result = subprocess.run([exe, "--prove", str(rel_model)], cwd=root, capture_output=True, text=True, timeout=120)
    combined = result.stdout + "\n" + result.stderr
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    out_txt.write_text(combined, encoding="utf-8")
    return {
        "available": True,
        "returncode": result.returncode,
        "note": f"proof output written to {out_txt.relative_to(root)}",
        "lemma_results": parse_lemma_results(combined),
        "wellformedness": "successful" if "All wellformedness checks were successful" in combined else "warning_or_not_reported",
    }


def write_md(path: Path, tamarin_status: Dict[str, Any]) -> None:
    lines = [
        "# PoIA Formal Verification Expansion",
        "",
        "## Lemma Result Table",
        "",
        "| Lemma | Property | Threat Mapping | Result |",
        "|---|---|---|---|",
    ]
    for lemma, prop, threat in LEMMA_MAP:
        result_text = "ready-to-run"
        if tamarin_status["available"]:
            result_text = tamarin_status.get("lemma_results", {}).get(lemma, "not reported")
        lines.append(f"| `{lemma}` | {prop} | {threat} | {result_text} |")
    lines.extend(
        [
            "",
            "## Repository Reproducibility",
            "",
            "Run from the repository root:",
            "",
            "```bash",
            "./scripts/run_tamarin_poia.sh",
            "```",
            "",
            "Expanded model:",
            "",
            "```text",
            "tamarin/poia_protocol.spthy",
            "```",
            "",
            f"Tamarin status: `{tamarin_status['note']}`",
            f"Wellformedness: `{tamarin_status.get('wellformedness', 'not run')}`",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate formal verification expansion artifacts.")
    parser.add_argument("--out-dir", default="experiments/formal_verification_expansion")
    parser.add_argument("--run-tamarin", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = root / args.out_dir
    model = root / "tamarin" / "poia_protocol.spthy"
    tamarin_status = run_tamarin(root, model, out / "tamarin_output.txt") if args.run_tamarin else {"available": False, "returncode": None, "note": "not run; use --run-tamarin", "lemma_results": {}}
    summary = {"experiment": "formal_verification_expansion", "lemmas": [{"lemma": a, "property": b, "threat_mapping": c} for a, b, c in LEMMA_MAP], "tamarin_status": tamarin_status}
    out.mkdir(parents=True, exist_ok=True)
    (out / "formal_verification_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_md(out / "formal_verification_table.md", tamarin_status)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
