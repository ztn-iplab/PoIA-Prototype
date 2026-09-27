#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

project_name="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR")}"
container_id="$(podman ps -q \
  --filter "label=io.podman.compose.project=$project_name" \
  --filter "label=io.podman.compose.service=poia-bank" | head -n 1)"
if [[ -z "$container_id" ]]; then
  echo "The poia-bank service is not running." >&2
  exit 1
fi

snapshot="$(mktemp "${TMPDIR:-/tmp}/poia-human-study.XXXXXX.db")"
trap 'rm -f "$snapshot"' EXIT
podman exec "$container_id" python -c '
import sqlite3, sys
source = sqlite3.connect("file:/data/bank.db?mode=ro", uri=True)
snapshot = sqlite3.connect(":memory:")
source.backup(snapshot)
source.close()
sys.stdout.buffer.write(snapshot.serialize())
snapshot.close()
' > "$snapshot"

run_id="${1:-}"
if [[ -z "$run_id" ]]; then
  run_id="$(python3 - "$snapshot" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
row = connection.execute(
    "SELECT study_run_id FROM poia_human_study_trials "
    "WHERE study_mode = 'spontaneous' "
    "GROUP BY study_run_id ORDER BY MAX(created_at) DESC LIMIT 1"
).fetchone()
connection.close()
if row:
    print(row[0])
PY
)"
fi

if [[ -z "$run_id" ]]; then
  echo "No spontaneous human-study run was found." >&2
  exit 1
fi

out_dir="${2:-experiments/human_study/exports/$run_id}"
mkdir -p "$out_dir"
python3 scripts/analyze_human_study.py \
  --db "$snapshot" \
  --out-dir "$out_dir" \
  --run-id "$run_id"

echo "Exported $run_id to $out_dir"
