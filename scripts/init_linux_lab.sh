#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This initializer is intended for the isolated Linux lab." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required: sudo apt install openssl" >&2
  exit 1
fi
if [[ -e "${ENV_FILE}" && "${1:-}" != "--force" ]]; then
  echo "Refusing to overwrite ${ENV_FILE}; use --force only for a new lab state." >&2
  exit 1
fi

umask 077
session_secret="$(openssl rand -hex 32)"
downstream_secret="$(openssl rand -hex 32)"

cat > "${ENV_FILE}" <<EOF
POIA_SESSION_SECRET=${session_secret}
POIA_DOWNSTREAM_SECRET=${downstream_secret}
POIA_ENABLED=true
POIA_TEST_MODE=false
POIA_EXPERIMENT_MODE=false
PUBLIC_BASE_URL=https://poia.local
WEB_RP_ID=poia.local
WEB_ORIGIN=https://poia.local
# Never derive an authenticator endpoint from a DHCP-assigned LAN address --
# run.sh refuses to start if this is set to a raw IP literal. Leave it empty
# so authenticator enrollment retains the stable PUBLIC_BASE_URL hostname
# while local DNS is free to follow whatever LAN IP the lab host has today.
POIA_AUTH_BASE_URLS=
POIA_HTTPS_PORT=443
POIA_HTTP_PORT=80
POIA_GENERATE_LAB_CA=true
POIA_CONFIGURE_LAB_DNS=true
POIA_SKIP_HOST_SETUP=false
EOF

echo "Created private lab configuration: ${ENV_FILE}"
echo "The file is ignored by Git. Do not copy it into reports or public artifacts."
