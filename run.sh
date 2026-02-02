#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: ./run.sh [--build]"
  echo "  --build   rebuild images before starting"
}

compose_bin=""
engine_bin=""

if command -v podman >/dev/null 2>&1; then
  if podman compose version >/dev/null 2>&1; then
    compose_bin="podman compose"
    engine_bin="podman"
  fi
fi

if [[ -z "${compose_bin}" ]] && command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    compose_bin="docker compose"
    engine_bin="docker"
  fi
fi

if [[ -z "${compose_bin}" ]]; then
  echo "Error: podman compose or docker compose is required."
  exit 1
fi

detect_host_ip() {
  local ip=""
  local iface=""
  if command -v route >/dev/null 2>&1; then
    iface=$(route get default 2>/dev/null | awk '/interface:/{print $2}' | tail -n 1)
    if [[ -n "${iface}" ]]; then
      ip=$(ipconfig getifaddr "${iface}" 2>/dev/null || true)
    fi
  fi
  if [[ -z "${ip}" ]]; then
    for iface in en0 en1 en2 en3 en4 en5 en6 en7 en8; do
      ip=$(ipconfig getifaddr "${iface}" 2>/dev/null || true)
      if [[ -n "${ip}" ]]; then
        echo "${ip}"
        return 0
      fi
    done
    return 1
  fi
  echo "${ip}"
  return 0
}

update_dns_mapping() {
  local ip="${1}"
  if [[ -z "${ip}" ]]; then
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
    echo "address=/poia.local/${ip}"
    echo "address=/localhost.localdomain/0.0.0.0"
    echo "address=/localhost.localdomain.com/0.0.0.0"
  } | sudo tee "${conf_dir}/poia.local.conf" >/dev/null

  sudo mkdir -p /etc/resolver
  sudo rm -f /etc/resolver/localhost.localdomain /etc/resolver/localhost.localdomain.com >/dev/null 2>&1 || true
  echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/poia.local >/dev/null

  if command -v sudo >/dev/null 2>&1; then
    sudo brew services restart dnsmasq >/dev/null 2>&1 || true
  fi
}

update_hosts_mapping() {
  local ip="${1}"
  if [[ -z "${ip}" ]]; then
    return 0
  fi
  sudo sh -c "grep -v ' poia.local' /etc/hosts > /tmp/poia-hosts"
  sudo sh -c "grep -v ' localhost.localdomain' /etc/hosts > /tmp/poia-hosts.clean"
  if [[ -f /tmp/poia-hosts.clean ]]; then
    sudo mv /tmp/poia-hosts.clean /tmp/poia-hosts
  fi
  echo "${ip} poia.local" | sudo tee -a /tmp/poia-hosts >/dev/null
  sudo mv /tmp/poia-hosts /etc/hosts
  echo "Mapped poia.local to ${ip} in /etc/hosts"
}

ensure_cert() {
  local cert_dir="${ROOT_DIR}/certs"
  local key_dir="${ROOT_DIR}/private"
  local ca_cert="${ROOT_DIR}/certs/zt-iam-ca.crt"
  local ca_key="${ROOT_DIR}/private/zt-iam-ca.key"
  local cert_path="${cert_dir}/poia.local.pem"
  local key_path="${key_dir}/poia.local-key.pem"

  mkdir -p "${cert_dir}" "${key_dir}"

  if [[ ! -f "${ca_cert}" || ! -f "${ca_key}" ]]; then
    echo "ZT-IAM CA files not found. Expected:"
    echo "  ${ca_cert}"
    echo "  ${ca_key}"
    exit 1
  fi

  if [[ -f "${cert_path}" && -f "${key_path}" ]]; then
    return 0
  fi

  echo "Generating poia.local certificate signed by ZT-IAM CA..."
  local csr_path="${cert_dir}/poia.local.csr"
  local ext_path="${cert_dir}/poia.local.ext"

  cat > "${ext_path}" <<EOF
subjectAltName=DNS:poia.local
EOF

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${key_path}" \
    -out "${csr_path}" \
    -subj "/CN=poia.local"

  openssl x509 -req -in "${csr_path}" \
    -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
    -out "${cert_path}" -days 3650 -sha256 -extfile "${ext_path}"

  rm -f "${csr_path}" "${ext_path}"
}

cleanup_ports() {
  local names=("poia-prototype-caddy-1" "ztn_nginx")
  for name in "${names[@]}"; do
    if ${engine_bin} ps -a --format "{{.Names}}" | grep -Fxq "${name}"; then
      ${engine_bin} stop "${name}" >/dev/null 2>&1 || true
      ${engine_bin} rm "${name}" >/dev/null 2>&1 || true
    fi
  done
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${engine_bin}" == "podman" ]]; then
  podman machine start >/dev/null 2>&1 || true
fi

host_ip=$(detect_host_ip || true)
update_dns_mapping "${host_ip}"
update_hosts_mapping "${host_ip}"
ensure_cert
cleanup_ports

export PUBLIC_BASE_URL="https://poia.local"
export WEB_RP_ID="poia.local"
export WEB_ORIGIN="https://poia.local"

echo "Using PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
if [[ -n "${host_ip}" ]]; then
  echo "LAN IP detected: ${host_ip}"
else
  echo "LAN IP not detected. Make sure poia.local resolves correctly."
fi

if [[ "${1:-}" == "--build" ]]; then
  ${compose_bin} build --no-cache poia-bank
  ${compose_bin} up -d
elif [[ -z "${1:-}" ]]; then
  ${compose_bin} up -d
else
  echo "Unknown option: ${1}"
  usage
  exit 1
fi
