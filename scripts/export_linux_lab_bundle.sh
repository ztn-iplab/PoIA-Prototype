#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${ROOT_DIR}/dist}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_NAME="poia-linux-lab-${STAMP}"
WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

for command_name in git tar sha256sum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
done
if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=no)" ]]; then
  echo "PoIA tracked working tree is dirty; commit or stash tracked changes first." >&2
  exit 1
fi

mkdir -p "${WORK_DIR}/${BUNDLE_NAME}" "${OUTPUT_DIR}"

snapshot_repository() {
  local source_dir="$1"
  local destination="$2"
  local source_commit
  source_commit="$(git -C "${source_dir}" rev-parse HEAD)"
  mkdir -p "${destination}"
  git -C "${source_dir}" archive HEAD | tar -x -C "${destination}"
  find "${destination}" -type f \
    \( -name '.env' -o -name '*.db' -o -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.pcap' -o -name '*.pcapng' \) \
    -delete
  printf '%s\n' "${source_commit}" > "${destination}/.export-source-commit"
  printf '%s\n' \
    "Excluded from snapshot: environment, database, certificate, key, and packet-capture files." \
    > "${destination}/.export-exclusions"
  git -C "${destination}" init -q -b main
  git -C "${destination}" config user.name "PoIA Lab Export"
  git -C "${destination}" config user.email "poia-lab-export@invalid.local"
  git -C "${destination}" add -A
  git -C "${destination}" commit -q -m "Sanitized lab snapshot from ${source_commit}"
}

snapshot_repository "${ROOT_DIR}" "${WORK_DIR}/${BUNDLE_NAME}/poia-prototype"

cat > "${WORK_DIR}/${BUNDLE_NAME}/EXPORT-MANIFEST.txt" <<EOF
Created UTC: ${STAMP}
PoIA source commit: $(git -C "${ROOT_DIR}" rev-parse HEAD)
Export policy: committed files only; no local history, environment, database, certificate, key, or raw-run files
External authenticator: not included; use the independently installed phone application
EOF

if find "${WORK_DIR}/${BUNDLE_NAME}" -path '*/.git' -prune -o -type f \
  \( -name '.env' -o -name '*.db' -o -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.pcap' -o -name '*.pcapng' \) -print | grep -q .; then
  echo "Sensitive filename policy failed; export aborted." >&2
  exit 1
fi
if grep -RIlE --exclude-dir=.git 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}' "${WORK_DIR}/${BUNDLE_NAME}" | grep -q .; then
  echo "Sensitive content policy failed; export aborted." >&2
  exit 1
fi

(
  cd "${WORK_DIR}/${BUNDLE_NAME}"
  find . -path '*/.git' -prune -o -type f ! -name 'FILES.sha256' -print0 \
    | sort -z | xargs -0 sha256sum > FILES.sha256
)

archive_path="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
tar -czf "${archive_path}" -C "${WORK_DIR}" "${BUNDLE_NAME}"
(
  cd "${OUTPUT_DIR}"
  sha256sum "${BUNDLE_NAME}.tar.gz" > "${BUNDLE_NAME}.tar.gz.sha256"
)

echo "Created sanitized Linux lab export:"
echo "  ${archive_path}"
echo "  ${archive_path}.sha256"
