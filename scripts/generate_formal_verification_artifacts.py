#!/usr/bin/env python3
"""Generate formal-verification expansion artifacts for PoIA."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


LEMMA_MAP = [
    ("protocol_executable", "Reachable honest approval and acceptance", "Non-vacuity check"),
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
        match = re.search(
            rf"^\s*{re.escape(lemma)}\s+\((?:all-traces|exists-trace)\):\s+([^\n]+)$",
            output,
            re.MULTILINE,
        )
        results[lemma] = match.group(1).strip() if match else "not reported"
    return results


def command_output(command: List[str], root: Path) -> str:
    return subprocess.check_output(command, cwd=root, text=True, stderr=subprocess.STDOUT).strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tamarin(root: Path, model: Path, out_txt: Path) -> Dict[str, Any]:
    exe = shutil.which("tamarin-prover")
    if not exe:
        return {"available": False, "returncode": None, "note": "tamarin-prover not found on PATH", "lemma_results": {}}
    rel_model = model.relative_to(root)
    started_at = int(time.time())
    result = subprocess.run([exe, "--prove", str(rel_model)], cwd=root, capture_output=True, text=True, timeout=300)
    completed_at = int(time.time())
    combined = result.stdout + "\n" + result.stderr
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    out_txt.write_text(combined, encoding="utf-8")
    return {
        "available": True,
        "returncode": result.returncode,
        "note": f"proof output written to {out_txt.relative_to(root)}",
        "lemma_results": parse_lemma_results(combined),
        "wellformedness": "successful" if "All wellformedness checks were successful" in combined else "warning_or_not_reported",
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": completed_at - started_at,
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
    parser.add_argument("--run-id")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = root / args.out_dir
    model = root / "tamarin" / "poia_protocol.spthy"
    if args.run_id and subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip():
        raise SystemExit("Track D confirmatory runs require a clean working tree")
    stem = args.run_id or "formal_verification"
    output_path = out / f"{stem}-tamarin-output.txt"
    summary_path = out / f"{stem}-summary.json"
    table_path = out / f"{stem}-table.md"
    tamarin_status = run_tamarin(root, model, output_path) if args.run_tamarin else {"available": False, "returncode": None, "note": "not run; use --run-tamarin", "lemma_results": {}}
    summary = {"experiment": "formal_verification_expansion", "run_id": args.run_id, "lemmas": [{"lemma": a, "property": b, "threat_mapping": c} for a, b, c in LEMMA_MAP], "tamarin_status": tamarin_status}
    out.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_md(table_path, tamarin_status)
    if args.run_id:
        exe = shutil.which("tamarin-prover")
        if not exe:
            raise SystemExit("tamarin-prover not found")
        manifest = {
            "run_id": args.run_id,
            "repository_commit": command_output(["git", "rev-parse", "HEAD"], root),
            "tree_clean": True,
            "command": f"tamarin-prover --prove {model.relative_to(root)}",
            "tamarin_version": command_output([exe, "--version"], root).splitlines()[1].strip(),
            "maude_version": command_output(["maude", "--version"], root).splitlines()[0].strip(),
            "python_version": platform.python_version(),
            "model_sha256": sha256_file(model),
            "runner_sha256": sha256_file(Path(__file__)),
            "preregistration_sha256": sha256_file(root / "docs" / "experiments" / "track_d_preregistration.md"),
        }
        manifest_path = out / f"{args.run_id}-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        required_results = tamarin_status.get("lemma_results", {})
        if tamarin_status.get("returncode") != 0 or tamarin_status.get("wellformedness") != "successful":
            raise SystemExit("Tamarin run failed or reported wellformedness warnings")
        if any(not required_results.get(lemma, "").startswith("verified") for lemma, _, _ in LEMMA_MAP):
            raise SystemExit("one or more fixed lemmas were not verified")
        checksum_path = out / f"{args.run_id}-checksums.sha256"
        artifacts = (model, Path(__file__), output_path, summary_path, table_path, manifest_path)
        checksum_path.write_text(
            "\n".join(f"{sha256_file(path)}  {path.relative_to(root)}" for path in artifacts) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
