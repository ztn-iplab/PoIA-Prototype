#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL="$ROOT_DIR/tamarin/poia_protocol.spthy"
OUT_DIR="$ROOT_DIR/tamarin/results"
OUT_FILE="$OUT_DIR/poia_protocol.txt"

mkdir -p "$OUT_DIR"

if ! command -v tamarin-prover >/dev/null 2>&1; then
  echo "tamarin-prover not found. Please install tamarin-prover and maude." >&2
  exit 1
fi

tamarin-prover --prove "$MODEL" | tee "$OUT_FILE"
