#!/usr/bin/env bash
# Installs or upgrades Graylog Server + Graylog Data Node + MongoDB.
# Supports Ubuntu 22.04/24.04 and RHEL 8/9.
# Logs to /var/log/server_install.log (stdout+stderr).
# Default Graylog admin credential: admin / admin

set -Eeuo pipefail

# ---------------- Logging ----------------
LOG_FILE="/var/log/server_install.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"

# Mirror to console and log file
exec > >(tee -a "$LOG_FILE") 2>&1

on_error() {
  local ec=$?
  echo "[x] ERROR at line ${BASH_LINENO[0]} (exit code $ec). See $LOG_FILE for details."
  exit "$ec"
}
trap on_error ERR

# ---------------- Helpers ----------------
log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[x]\e[0m $*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; exit 1; }; }

[[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }

need curl
need sed
need awk
need tee

source /etc/os-release
ID_LIKE="${ID_LIKE:-}"
OS="$ID"
VER_ID="$VERSION_ID"
log "Detected OS: $PRETTY_NAME"

# Package manager family
if [[ "$ID" == "ubuntu" ]] || [[ "$ID_LIKE" == *"debian"* ]]; then
  PM="apt"
  export DEBIAN_FRONTEND=noninteractive
elif [[ "$ID" == "rhel" ]] || [[ "$ID_LIKE" == *"rhel"* ]] || [[ "$ID_LIKE" == *"fedora"* ]] || [[ "$ID_LIKE" == *"centos"* ]]; then
  PM="dnf"
else
  err "Unsupported distribution: $PRETTY_NAME"
  exit 2
fi

# ---------------- Constants ----------------
GL_REPO_BASE="https://packages.graylog2.org/repo/packages"
GL_MAJORS=(6.1 6.0 5.2 5.1 5.0)     # try in order
MONGO_MAJOR_UBU="8.0"
MONGO_MAJOR_RHEL="8.0"              # falls back to 7.0 if needed

ADMIN_PLAIN="admin"
ADMIN_SHA256="$(printf '%s' "$ADMIN_PLAIN" | sha256sum | awk '{print $1}')"

# If set to "true" the Data Node preflight is skipped (lab only)
SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-false}"

# ---------------- Repo setup ----------------
add_graylog_repo_apt() {
  for ver in "${GL_MAJORS[@]}"; do
    local pkg="graylog-${ver}-repository_latest.deb"
    local url="${GL_REPO_BASE}/${pkg}"
    if curl -fsIL "$url" >/dev/null; then
      log "Adding Graylog APT repo ($ver)"
      curl -fsSL "$url" -o "/tmp/${pkg}"
      dpkg -i "/tmp/${pkg}"
      return 0
    fi
  done
  err "No Graylog APT repo package found."
  exit 3
}

add_graylog_repo_rpm() {
  for ver in "${GL_MAJORS[@]}"; do
    local pkg="graylog-${ver}-repository_latest.rpm"
    local url="${GL_REPO_BASE}/${pkg}"
    if curl -fsIL "$url" >/dev/null; then
      log "Adding Graylog RPM repo ($ver)"
      rpm -Uvh "$url"
      return 0
    fi
  done
  err "No Graylog RPM repo package found."
  exit 3
}

# ---------------- MongoDB install ----------------
install_mongodb_apt() {
  log "Installing MongoDB ${MONGO_MAJOR_UBU} (Ubuntu)"
  apt-get update -y
  apt-get install -y gnupg curl ca-certificates lsb-release
  curl -fsSL "https://www.mongodb.org/static/pgp/server-${MONGO_MAJOR_UBU}.asc" \
    | gpg --dearmor -o /usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg
  UB_CODENAME=$(. /etc/os-release; echo "$VERSION_CODENAME")
  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg] https://repo.mongodb.org/apt/ubuntu ${UB_CODENAME}/mongodb-org/${MONGO_MAJOR_UBU} multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-${MONGO_MAJOR_UBU}.list
  apt-get update -y
  apt-get install -y mongodb-org
  systemctl enable --now mongod
}

install_mongodb_rpm() {
  log "Installing MongoDB ${MONGO_MAJOR_RHEL} (RHEL)"
  cat >/etc/yum.repos.d/mongodb-org-${MONGO_MAJOR_RHEL}.repo <<EOF
[mongodb-org-${MONGO_MAJOR_RHEL}]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/${MONGO_MAJOR_RHEL}/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-${MONGO_MAJOR_RHEL}.asc
EOF
  if ! dnf -y install mongodb-org; then
    warn "Falling back to MongoDB 7.0"
    sed -i "s/${MONGO_MAJOR_RHEL}/7.0/g" /etc/yum.repos.d/mongodb-org-*.repo
    dnf clean all -y || true
    dnf -y install mongodb-org
  fi
  systemctl enable --now mongod
}

# ---------------- Graylog install ----------------
install_graylog_stack_apt() {
  add_graylog_repo_apt
  apt-get update -y
  apt-get install -y openjdk-17-jre-headless || apt-get install -y openjdk-11-jre-headless
  apt-get install -y graylog-datanode graylog-server
}

install_graylog_stack_rpm() {
  add_graylog_repo_rpm
  dnf -y install java-17-openjdk || dnf -y install java-11-openjdk
  dnf -y install graylog-datanode graylog-server
}

# ---------------- Config helpers ----------------
set_kv() {
  # set_kv <file> <key> <value>
  local file="$1" key="$2" val="$3"
  if grep -qE "^[# ]*${key}\s*=" "$file" 2>/dev/null; then
    sed -i -E "s|^[# ]*${key}\s*=.*|${key} = ${val}|" "$file"
  else
    echo "${key} = ${val}" >> "$file"
  fi
}

# ---------------- Server config ----------------
PASSWORD_SECRET=""
configure_server() {
  local conf="/etc/graylog/server/server.conf"
  log "Configuring Graylog server: $conf"
  mkdir -p /etc/graylog/server
  [[ -f "$conf" ]] || cp /usr/share/graylog-server/server.conf "$conf"

  # Ensure password_secret exists (shared with Data Node)
  PASSWORD_SECRET="$(awk -F= '/^password_secret/ {print $2}' "$conf" | xargs || true)"
  if [[ -z "$PASSWORD_SECRET" ]]; then
    if command -v openssl >/dev/null 2>&1; then
      PASSWORD_SECRET="$(openssl rand -base64 96 | tr -d '\n')"
    else
      PASSWORD_SECRET="$(head -c 96 /dev/urandom | base64 | tr -d '\n')"
    fi
    set_kv "$conf" "password_secret" "$PASSWORD_SECRET"
  else
    set_kv "$conf" "password_secret" "$PASSWORD_SECRET"
  fi

  # Set admin password (admin/admin) and sane defaults
  set_kv "$conf" "root_password_sha2" "$ADMIN_SHA256"
  set_kv "$conf" "is_master" "true"
  set_kv "$conf" "root_email" "admin@example.org"
  set_kv "$conf" "root_timezone" "UTC"
  set_kv "$conf" "http_bind_address" "0.0.0.0:9000"
  set_kv "$conf" "http_publish_uri" "http://127.0.0.1:9000/"

  # Comment out legacy external store hosts when using Data Node
  sed -i 's/^\s*\(elasticsearch_hosts\|opensearch_hosts\)\s*=.*$/# &/' "$conf" || true

  systemctl daemon-reload
  systemctl enable graylog-server.service
}

# ---------------- Data Node config (patched) ----------------
configure_datanode() {
  local conf="/etc/graylog/datanode/datanode.conf"
  log "Configuring Graylog Data Node: $conf"
  mkdir -p /etc/graylog/datanode
  [[ -f "$conf" ]] || touch "$conf"
  cp -a "$conf" "${conf}.bak.$(date +%s)" || true

  # Ports & binding
  set_kv "$conf" "bind_address" "0.0.0.0"
  set_kv "$conf" "datanode_http_port" "8999"
  set_kv "$conf" "opensearch_http_port" "9200"
  set_kv "$conf" "opensearch_network_host" "0.0.0.0"

  # Mongo connection and shared secret
  set_kv "$conf" "mongodb_uri" "mongodb://127.0.0.1:27017/graylog"
  set_kv "$conf" "password_secret" "$PASSWORD_SECRET"

  # Optional: bypass preflight (lab only)
  if [[ "${SKIP_PREFLIGHT,,}" == "true" ]]; then
    set_kv "$conf" "skip_preflight_checks" "true"
  fi

  # Heap size heuristic (if not already set)
  if ! grep -q '^opensearch_heap' "$conf" 2>/dev/null; then
    if [[ -r /proc/meminfo ]]; then
      local mem_kb half_gb
      mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
      half_gb=$(( (mem_kb/1024/1024)/2 ))
      [[ $half_gb -lt 1 ]] && half_gb=1
      [[ $half_gb -gt 8 ]] && half_gb=8
      echo "opensearch_heap = ${half_gb}g" >> "$conf"
    else
      echo "opensearch_heap = 2g" >> "$conf"
    fi
  fi

  # Kernel and systemd prerequisites for OpenSearch
  echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-graylog.conf
  sysctl --system

  mkdir -p /etc/systemd/system/graylog-datanode.service.d
  cat > /etc/systemd/system/graylog-datanode.service.d/override.conf <<'EOF'
[Service]
LimitNOFILE=65536
LimitMEMLOCK=infinity
EOF

  systemctl daemon-reload
  systemctl enable graylog-datanode.service

  # Ensure directories & ownership (best-effort)
  mkdir -p /var/lib/graylog-datanode /var/log/graylog-datanode
  for u in graylog graylog-datanode; do
    if id "$u" >/dev/null 2>&1; then
      chown -R "$u":"$u" /var/lib/graylog-datanode /var/log/graylog-datanode || true
    fi
  done
}

# ---------------- Firewall (best-effort) ----------------
open_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 9000/tcp || true
    ufw allow 1514/tcp || true
    ufw allow 1514/udp || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --add-port=9000/tcp --permanent || true
    firewall-cmd --add-port=1514/tcp --permanent || true
    firewall-cmd --add-port=1514/udp --permanent || true
    firewall-cmd --reload || true
  fi
}

# ---------------- Wait for ports ----------------
wait_for_port() {
  local port="$1" timeout="${2:-120}"
  log "Waiting for TCP :$port (timeout ${timeout}s)…"
  for ((i=0;i<timeout;i++)); do
    if ss -ltn | grep -q ":${port} "; then
      log "Port :$port is listening."
      return 0
    fi
    sleep 1
  done
  err "Timeout waiting for port :$port"
  return 1
}

# ---------------- Execute ----------------
if [[ "$PM" == "apt" ]]; then
  log "Using APT flow"
  install_mongodb_apt
  install_graylog_stack_apt
elif [[ "$PM" == "dnf" ]]; then
  log "Using DNF flow"
  install_mongodb_rpm
  install_graylog_stack_rpm
fi

configure_server
configure_datanode
open_firewall

# Start/restart services
systemctl restart graylog-datanode
systemctl restart graylog-server

# Wait for listeners (Data Node first, then UI)
wait_for_port 8999 180
wait_for_port 9200 180
wait_for_port 9000 180

# ---------------- Summary ----------------
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "${HOST_IP}" ]] && HOST_IP="127.0.0.1"

log "Services brief status:"
systemctl --no-pager --full status mongod | sed -n '1,5p' || true
systemctl --no-pager --full status graylog-datanode | sed -n '1,5p' || true
systemctl --no-pager --full status graylog-server | sed -n '1,10p' || true

cat <<EOF

=========================================================
 Graylog installation/upgrade completed.

 UI:        http://${HOST_IP}:9000/
 Login:     admin / admin   (CHANGE THIS IMMEDIATELY)
 Log file:  ${LOG_FILE}
=========================================================
EOF
