#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

usage() {
  echo "Usage: ./run.sh [--resume|--stop|--status|--logs|--build|--check]"
  echo "  --resume  refresh configuration and start without rebuilding"
  echo "  --stop    stop this project's containers while preserving data"
  echo "  --status  show this project's container state"
  echo "  --logs    show the latest project logs"
  echo "  --build   explicitly rebuild images, then start"
  echo "  --check   validate runtime and print detected configuration"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

compose_cmd=()
engine_bin=""

prefer_docker=false
if [[ "$(uname -s)" == "Linux" ]]; then
  prefer_docker=true
fi

try_docker_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    compose_cmd=(docker compose)
    engine_bin="docker"
    return 0
  fi
  return 1
}

try_podman_compose() {
  if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    compose_cmd=(podman compose)
    engine_bin="podman"
    return 0
  fi
  if command -v podman-compose >/dev/null 2>&1; then
    compose_cmd=(podman-compose)
    engine_bin="podman"
    return 0
  fi
  return 1
}

if [[ "${prefer_docker}" == "true" ]]; then
  try_docker_compose || try_podman_compose || true
else
  try_podman_compose || try_docker_compose || true
fi

if [[ ${#compose_cmd[@]} -eq 0 ]]; then
  echo "Error: install one of: docker compose, podman compose, or podman-compose." >&2
  echo "Ubuntu/Debian examples:" >&2
  echo "  sudo apt install docker.io docker-compose-v2" >&2
  echo "  sudo apt install podman podman-compose" >&2
  exit 1
fi

detect_host_ip() {
  local ip=""
  local iface=""
  if [[ "$(uname -s)" == "Darwin" ]] && command -v route >/dev/null 2>&1; then
    iface=$(route get default 2>/dev/null | awk '/interface:/{print $2}' | tail -n 1)
    if [[ -n "${iface}" ]]; then
      ip=$(ipconfig getifaddr "${iface}" 2>/dev/null || true)
    fi
  fi
  if [[ -z "${ip}" && "$(uname -s)" == "Darwin" ]]; then
    for iface in en0 en1 en2 en3 en4 en5 en6 en7 en8; do
      ip=$(ipconfig getifaddr "${iface}" 2>/dev/null || true)
      if [[ -n "${ip}" ]]; then
        echo "${ip}"
        return 0
      fi
    done
  fi
  if [[ -z "${ip}" ]] && command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
  fi
  if [[ -z "${ip}" ]] && command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i !~ /^127\./) {print $i; exit}}')
  fi
  if [[ -z "${ip}" ]]; then
    return 1
  fi
  echo "${ip}"
  return 0
}

update_dns_mapping() {
  local ip="${1}"
  local hostname="${POIA_HOSTNAME:-poia.local}"
  if [[ -z "${ip}" ]]; then
    return 0
  fi

  if [[ "$(uname -s)" == "Linux" ]]; then
    if [[ "${POIA_CONFIGURE_LAB_DNS:-false}" != "true" ]]; then
      echo "Lab DNS setup disabled; set POIA_CONFIGURE_LAB_DNS=true to manage dnsmasq."
      return 0
    fi
    if ! command -v dnsmasq >/dev/null 2>&1; then
      echo "dnsmasq is not installed; install it or configure poia.local in lab DNS." >&2
      return 1
    fi
    {
      echo "address=/${hostname}/${ip}"
      echo "listen-address=127.0.0.1,${ip}"
    } | sudo tee /etc/dnsmasq.d/poia-local.conf >/dev/null
    sudo systemctl restart dnsmasq
    echo "Lab DNS maps ${hostname} to ${ip}; set the test phone DNS server to ${ip}."
    return 0
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Skipping dnsmasq update."
    return 0
  fi

  local conf_dir
  conf_dir="$(brew --prefix)/etc/dnsmasq.d"
  mkdir -p "${conf_dir}"

  rm -f "${conf_dir}/poia.local.conf"
  rm -f "${conf_dir}/zt-iam.conf"
  rm -f "${conf_dir}/localhost.localdomain.com.conf"
  if [[ -f "$(brew --prefix)/etc/dnsmasq.conf" ]]; then
    sed -i.bak -E "/poia\.local/d" "$(brew --prefix)/etc/dnsmasq.conf"
    sed -i.bak -E "/localhost\\.localdomain(\\.com)?/d" "$(brew --prefix)/etc/dnsmasq.conf"
    rm -f "$(brew --prefix)/etc/dnsmasq.conf.bak"
  fi

  {
    echo "address=/${hostname}/${ip}"
    echo "listen-address=127.0.0.1,${ip}"
    echo "bind-dynamic"
    echo "address=/localhost.localdomain/0.0.0.0"
    echo "address=/localhost.localdomain.com/0.0.0.0"
  } | sudo tee "${conf_dir}/poia.local.conf" >/dev/null

  sudo mkdir -p /etc/resolver
  sudo rm -f /etc/resolver/localhost.localdomain /etc/resolver/localhost.localdomain.com >/dev/null 2>&1 || true
  echo "nameserver 127.0.0.1" | sudo tee "/etc/resolver/${hostname}" >/dev/null

  if command -v sudo >/dev/null 2>&1; then
    if ! (cd /tmp && sudo brew services restart dnsmasq); then
      echo "Failed to restart dnsmasq; poia.local will not be reachable from authenticators." >&2
      return 1
    fi
  fi
}

update_hosts_mapping() {
  local ip="${1}"
  local hostname="${POIA_HOSTNAME:-poia.local}"
  if [[ -z "${ip}" ]]; then
    return 0
  fi
  local hosts_tmp
  hosts_tmp=$(mktemp)
  awk -v host="${hostname}" '$0 !~ "(^|[[:space:]])" host "([[:space:]]|$)" && $0 !~ "(^|[[:space:]])localhost\\.localdomain(\\.com)?([[:space:]]|$)"' /etc/hosts > "${hosts_tmp}"
  echo "${ip} ${hostname}" >> "${hosts_tmp}"
  sudo install -m 0644 "${hosts_tmp}" /etc/hosts
  rm -f "${hosts_tmp}"
  echo "Mapped ${hostname} to ${ip} in /etc/hosts"
}

ensure_cert() {
  local hostname="${POIA_HOSTNAME:-poia.local}"
  local host_ip="${1:-}"
  local cert_dir="${ROOT_DIR}/certs"
  local key_dir="${ROOT_DIR}/private"
  local ca_cert="${ROOT_DIR}/certs/zt-iam-ca.crt"
  local ca_key="${ROOT_DIR}/private/zt-iam-ca.key"
  local cert_path="${cert_dir}/poia.local.pem"
  local key_path="${key_dir}/poia.local-key.pem"

  mkdir -p "${cert_dir}" "${key_dir}"

  if [[ ! -f "${ca_cert}" || ! -f "${ca_key}" ]]; then
    if [[ "${POIA_GENERATE_LAB_CA:-false}" != "true" ]]; then
      echo "ZT-IAM CA files not found. Expected:"
      echo "  ${ca_cert}"
      echo "  ${ca_key}"
      echo "For an isolated lab, set POIA_GENERATE_LAB_CA=true to create new lab-only trust material."
      exit 1
    fi
    echo "Generating a new lab-only certificate authority..."
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
      -keyout "${ca_key}" -out "${ca_cert}" \
      -subj "/CN=PoIA Isolated Lab CA"
    chmod 600 "${ca_key}"
  fi

  if [[ -f "${cert_path}" && -f "${key_path}" ]]; then
    return 0
  fi

  echo "Generating poia.local certificate signed by ZT-IAM CA..."
  local csr_path="${cert_dir}/poia.local.csr"
  local ext_path="${cert_dir}/poia.local.ext"

  if [[ -n "${host_ip}" ]]; then
    cat > "${ext_path}" <<EOF
subjectAltName=DNS:${hostname},IP:${host_ip}
EOF
  else
    cat > "${ext_path}" <<EOF
subjectAltName=DNS:${hostname}
EOF
  fi

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${key_path}" \
    -out "${csr_path}" \
    -subj "/CN=${hostname}"

  openssl x509 -req -in "${csr_path}" \
    -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
    -out "${cert_path}" -days 3650 -sha256 -extfile "${ext_path}"

  rm -f "${csr_path}" "${ext_path}"
}

post_start_check() {
  # The bank container can acquire a new IP; refresh nginx's cached upstream.
  "${compose_cmd[@]}" exec -T nginx nginx -t
  "${compose_cmd[@]}" exec -T nginx nginx -s reload
  local nginx_ps=""
  nginx_ps="$("${compose_cmd[@]}" ps nginx 2>/dev/null || true)"
  if ! printf '%s\n' "${nginx_ps}" | grep -Eiq 'Up|running'; then
    echo "nginx is not running after startup. Recent nginx logs:" >&2
    "${compose_cmd[@]}" logs --tail=120 nginx >&2 || true
    echo "Check that certs/poia.local.pem and private/poia.local-key.pem exist before starting nginx." >&2
    exit 1
  fi

  if command -v curl >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/certs/zt-iam-ca.crt" ]]; then
    local url="${PUBLIC_BASE_URL:-https://poia.local}/login"
    local http_code
    http_code="$(curl --cacert "${ROOT_DIR}/certs/zt-iam-ca.crt" \
      --connect-timeout 8 -o /dev/null -s -w '%{http_code}' "${url}" || true)"
    if [[ "${http_code}" != "200" ]]; then
      echo "Warning: ${url} returned HTTP ${http_code:-unreachable} after startup." >&2
      echo "Run './run.sh --logs' and verify that poia.local resolves to this host." >&2
    else
      echo "HTTPS health check passed: ${url}"
    fi
  fi
}

if [[ "${engine_bin}" == "podman" && "$(uname -s)" == "Darwin" ]]; then
  podman machine start >/dev/null 2>&1 || true
fi

host_ip=$(detect_host_ip || true)
if [[ "${1:-}" == "--check" ]]; then
  echo "Compose command: ${compose_cmd[*]}"
  echo "Container engine: ${engine_bin}"
  echo "Detected LAN IP: ${host_ip:-unavailable}"
  echo "PUBLIC_BASE_URL=${PUBLIC_BASE_URL:-https://poia.local}"
  echo "POIA_AUTH_BASE_URLS=${POIA_AUTH_BASE_URLS:-<empty>}"
  echo "WEB_RP_ID=${WEB_RP_ID:-poia.local}"
  echo "WEB_ORIGIN=${WEB_ORIGIN:-https://poia.local}"
  exit 0
fi

if [[ "${1:-}" == "--stop" ]]; then
  "${compose_cmd[@]}" stop
  echo "PoIA containers stopped; named volumes and enrolled state are preserved."
  exit 0
fi
if [[ "${1:-}" == "--status" ]]; then
  "${compose_cmd[@]}" ps
  exit 0
fi
if [[ "${1:-}" == "--logs" ]]; then
  "${compose_cmd[@]}" logs --tail=100
  exit 0
fi

if [[ "${POIA_SKIP_HOST_SETUP:-false}" == "true" ]]; then
  echo "Skipping privileged DNS and hosts-file setup."
else
  update_dns_mapping "${host_ip}"
  update_hosts_mapping "${host_ip}"
fi
ensure_cert "${host_ip}"

export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://poia.local}"
export WEB_RP_ID="${WEB_RP_ID:-poia.local}"
export WEB_ORIGIN="${WEB_ORIGIN:-https://poia.local}"
# Never derive an authenticator endpoint from a DHCP address. Enrollment
# records retain the stable PUBLIC_BASE_URL hostname while DNS follows the LAN.
export POIA_AUTH_BASE_URLS="${POIA_AUTH_BASE_URLS:-}"

if [[ "$(uname -s)" == "Linux" && "${POIA_AUTH_BASE_URLS}" =~ https?://([0-9]{1,3}\.){3}[0-9]{1,3}([:/]|$) ]]; then
  echo "Refusing DHCP-derived POIA_AUTH_BASE_URLS=${POIA_AUTH_BASE_URLS}" >&2
  echo "Clear POIA_AUTH_BASE_URLS in .env; authenticators must retain the stable PUBLIC_BASE_URL hostname." >&2
  exit 1
fi

echo "Using PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
if [[ -n "${POIA_AUTH_BASE_URLS:-}" ]]; then
  echo "Using POIA_AUTH_BASE_URLS=${POIA_AUTH_BASE_URLS}"
fi
if [[ -n "${host_ip}" ]]; then
  echo "LAN IP detected: ${host_ip}"
else
  echo "LAN IP not detected. Make sure poia.local resolves correctly."
fi

if [[ "${1:-}" == "--build" ]]; then
  "${compose_cmd[@]}" build --no-cache poia-bank
  "${compose_cmd[@]}" up -d
  post_start_check
elif [[ "${1:-}" == "--resume" ]]; then
  if ! "${compose_cmd[@]}" up -d --no-build; then
    echo "Existing images were not found. Use ./run.sh --build only for the first start." >&2
    exit 1
  fi
  post_start_check
elif [[ -z "${1:-}" ]]; then
  "${compose_cmd[@]}" up -d
  post_start_check
else
  echo "Unknown option: ${1}"
  usage
  exit 1
fi
