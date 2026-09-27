#!/usr/bin/env python3
"""Verify every checksum manifest shipped with this artifact.

Each experiment package records the SHA-256 of its inputs and outputs in a
``*checksums.sha256`` file. Two conventions are in use: some list paths from
the repository root, others from the package directory. This script accepts
either, so a reader can confirm in one command that nothing in the release has
been altered since the run that produced it.

    python3 scripts/verify_artifact_checksums.py

Exit status is non-zero if any recorded file is missing or its digest differs.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entries(manifest: Path):
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        want, _, name = line.partition(" ")
        name = name.lstrip("*").strip()
        if want and name:
            yield want.lower(), name


def check(manifest: Path, base: Path):
    """Return (ok, failures) for one manifest resolved against one base."""
    failures = []
    for want, name in entries(manifest):
        target = base / name
        if not target.is_file():
            failures.append(f"{name}: missing")
        elif digest(target) != want:
            failures.append(f"{name}: digest differs")
    return not failures, failures


def main() -> int:
    manifests = sorted(ROOT.rglob("*checksums.sha256"))
    manifests = [m for m in manifests if ".git" not in m.parts]
    if not manifests:
        print("no checksum manifests found", file=sys.stderr)
        return 1

    verified = 0
    files = 0
    broken = []
    for manifest in manifests:
        rel = manifest.relative_to(ROOT)
        count = sum(1 for _ in entries(manifest))
        ok, _ = check(manifest, ROOT)
        base = "repository root"
        if not ok:
            ok, failures = check(manifest, manifest.parent)
            base = "package directory"
        if ok:
            verified += 1
            files += count
            print(f"ok    {rel}  ({count} files, {base})")
        else:
            broken.append((rel, failures))
            print(f"FAIL  {rel}")
            for failure in failures:
                print(f"        {failure}")

    print()
    print(f"{verified}/{len(manifests)} manifests verified, {files} files checked")
    if broken:
        print(f"{len(broken)} manifest(s) did not verify", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
