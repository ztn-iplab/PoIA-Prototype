#!/usr/bin/env python3
"""Check the source register embedded in the reproduction guide."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs/experiments/REPRODUCTION.md"


def main() -> int:
    try:
        block = REGISTER.read_text().split("<!-- evidence-register -->", 1)[1]
        register = json.loads(block.split("```json", 1)[1].split("```", 1)[0])
    except (OSError, IndexError, ValueError) as exc:
        print(json.dumps({"failures": [f"Invalid consolidated register: {exc}"]}))
        return 1
    failures = []
    sources = list(register["sources"])
    for source in register["sources"]:
        if source.get("manifest"):
            manifest = ROOT / source["source"]
            if manifest.is_file():
                sources.extend({"source": path, "sha256": digest}
                               for path, digest in json.loads(manifest.read_text())["sha256"].items())
    for source in sources:
        path = ROOT / source["source"]
        if not path.is_file():
            failures.append(f"Missing source: {source['source']}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
            failures.append(f"Changed source requires review: {source['source']}")
    print(json.dumps({"reviewed_sources": len(sources), "failures": failures,
                      "empirical_status": register["empirical_status"],
                      "scope": "File identity only; not independent validation of experimental claims."}, indent=2))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
