#!/usr/bin/env bash
set -euo pipefail

# =========================
# Graylog one-shot installer/upgrader
#  - Ubuntu 22.04/24.04 (apt)
#  - RHEL 8/9 (dnf)
# Components:
#   - MongoDB (official repo)
#   - Graylog Data Node (bundles/controls OpenSearch)
#   - Graylog Server
# =========================

# ---------- Helpers ----------
log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[x]\e[0m $*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }; }

need curl
need sed
need tee

if [[ $EUID -ne 0 ]]; then
  err "Please run as root (use sudo)."
  exit 1
fi

source /etc/os-release
ID_LIKE="${ID_LIKE:-}"
OS="$ID"
VER_ID="$VERSION_ID"

log "Detected OS: $PRETTY_NAME"

# Decide package manager family
if [[ "$ID" == "ubuntu" ]] || [[ "$ID_LIKE" == *"debian"* ]]; then
  PM="apt"
elif [[ "$ID" == "rhel" ]] || [[ "$ID_LIKE" == *"rhel"* ]] || [[ "$ID_LIKE" == *"fedora"* ]] || [[ "$ID_LIKE" == *"centos"* ]]; then
  PM="dnf"
else
  err "Unsupported distribution: $PRETTY_NAME"
  exit 2
fi

# ---------- Common variables ----------
GL_REPO_BASENAME_DEB="https://packages.graylog2.org/repo/packages"
GL_REPO_BASENAME_RPM="https://packages.graylog2.org/repo/packages"
# Try latest major first, then fall back
GL_MAJORS=(6.1 6.0 5.2 5.1 5.0)

MONGO_MAJOR_UBU="8.0"
MONGO_MAJOR_RHEL="8.0"   # falls back to 7.0 if unavailable

ADMIN_PLAIN="admin"
ADMIN_SHA256="$(printf '%s' "$ADMIN_PLAIN" | sha256sum | awk '{print $1}')"
PASSWORD_SECRET="$(openssl rand -base64 96 | tr -d '\n' || true)"
[[ -n "$PASSWORD_SECRET" ]] || PASSWORD_SECRET="$(head -c 96 /dev/urandom | base64 | tr -d '\n')"

# ---------- Functions per family ----------
add_graylog_repo_apt() {
  for ver in "${GL_MAJORS[@]}"; do
    pkg="graylog-${ver}-repository_latest.deb"
    url="${GL_REPO_BASENAME_DEB}/${pkg}"
    if curl -fsIL "$url" >/dev/null 2>&1; then
      log "Adding Graylog APT repo ($ver)"
      curl -fsSL "$url" -o "/tmp/${pkg}"
      dpkg -i "/tmp/${pkg}"
      return 0
    fi
  done
  err "Could not resolve a Graylog APT repository package."
  exit 3
}

add_graylog_repo_rpm() {
  for ver in "${GL_MAJORS[@]}"; do
    pkg="graylog-${ver}-repository_latest.rpm"
    url="${GL_REPO_BASENAME_RPM}/${pkg}"
    if curl -fsIL "$url" >/dev/null 2>&1; then
      log "Adding Graylog RPM repo ($ver)"
      rpm -Uvh "$url"
      return 0
    fi
  done
  err "Could not resolve a Graylog RPM repository package."
  exit 3
}

install_mongodb_apt() {
  log "Adding MongoDB ${MONGO_MAJOR_UBU} APT repo"
  apt-get update -y
  apt-get install -y gnupg curl ca-certificates
  curl -fsSL "https://www.mongodb.org/static/pgp/server-${MONGO_MAJOR_UBU}.asc" \
    | gpg --dearmor -o /usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg
  UB_CODENAME=$(. /etc/os-release; echo "$VERSION_CODENAME")
  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg] https://repo.mongodb.org/apt/ubuntu ${UB_CODENAME}/mongodb-org/${MONGO_MAJOR_UBU} multiverse" \
    | tee /etc/apt/sources.list.d/mongodb-org-${MONGO_MAJOR_UBU}.list >/dev/null
  apt-get update -y
  apt-get install -y mongodb-org
  systemctl enable --now mongod
}

install_mongodb_rpm() {
  local major="$MONGO_MAJOR_RHEL"
  log "Adding MongoDB ${major} YUM repo"
  cat >/etc/yum.repos.d/mongodb-org-${major}.repo <<EOF
[mongodb-org-${major}]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/${major}/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-${major}.asc
EOF
  if ! dnf -y install mongodb-org; then
    warn "Falling back to MongoDB 7.0 repo…"
    major="7.0"
    sed -i "s/${MONGO_MAJOR_RHEL}/${major}/g" /etc/yum.repos.d/mongodb-org-*.repo
    dnf clean all -y || true
    dnf -y install mongodb-org
  fi
  systemctl enable --now mongod
}

install_graylog_stack_apt() {
  add_graylog_repo_apt
  apt-get update -y
  # Java (Graylog/Datanode bundle uses its own JRE, but install OpenJDK for tools)
  apt-get install -y openjdk-17-jre-headless || apt-get install -y openjdk-11-jre-headless
  # Graylog Data Node + Server
  apt-get install -y graylog-datanode graylog-server
}

install_graylog_stack_rpm() {
  add_graylog_repo_rpm
  dnf -y install java-17-openjdk || dnf -y install java-11-openjdk
  dnf -y install graylog-datanode graylog-server
}

configure_datanode() {
  local f="/etc/graylog/datanode/datanode.conf"
  log "Configuring Graylog Data Node: $f"
  mkdir -p /etc/graylog/datanode
  touch "$f"

  # Ensure minimal required keys exist or are updated
  grep -q '^bind_address' "$f" 2>/dev/null || echo "bind_address = 0.0.0.0" >> "$f"
  # Heap: half RAM up to 8g if not set
  if ! grep -q '^opensearch_heap' "$f" 2>/dev/null; then
    # simple heuristic: half of MemTotal in GiB capped to 8g
    if command -v awk >/dev/null && [[ -r /proc/meminfo ]]; then
      mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
      half_gb=$(( (mem_kb/1024/1024)/2 ))
      [[ $half_gb -lt 1 ]] && half_gb=1
      [[ $half_gb -gt 8 ]] && half_gb=8
      echo "opensearch_heap = ${half_gb}g" >> "$f"
    else
      echo "opensearch_heap = 2g" >> "$f"
    fi
  fi

  # MongoDB URI (Data Node needs it)
  if ! grep -q '^mongodb_uri' "$f" 2>/dev/null; then
    echo "mongodb_uri = mongodb://127.0.0.1:27017/graylog" >> "$f"
  fi

  systemctl daemon-reload
  systemctl enable graylog-datanode.service
  systemctl restart graylog-datanode.service
}

configure_server() {
  local f="/etc/graylog/server/server.conf"
  log "Configuring Graylog Server: $f"
  mkdir -p /etc/graylog/server
  [[ -f "$f" ]] || cp /usr/share/graylog-server/server.conf "$f"

  # password_secret
  if grep -q '^password_secret\s*=' "$f"; then
    sed -i "s|^password_secret\s*=.*|password_secret = ${PASSWORD_SECRET}|" "$f"
  else
    echo "password_secret = ${PASSWORD_SECRET}" >> "$f"
  fi

  # root_password_sha2 (admin / admin)
  if grep -q '^root_password_sha2\s*=' "$f"; then
    sed -i "s|^root_password_sha2\s*=.*|root_password_sha2 = ${ADMIN_SHA256}|" "$f"
  else
    echo "root_password_sha2 = ${ADMIN_SHA256}" >> "$f"
  fi

  # Basic, sane defaults (idempotent appends)
  sed -i "s|^#\?is_master\s*=.*|is_master = true|" "$f"
  sed -i "s|^#\?root_email\s*=.*|root_email = admin@example.org|" "$f"
  sed -i "s|^#\?root_timezone\s*=.*|root_timezone = UTC|" "$f"

  # HTTP bind/open to all; publish local (adjust as needed)
  if grep -q '^http_bind_address\s*=' "$f"; then
    sed -i "s|^http_bind_address\s*=.*|http_bind_address = 0.0.0.0:9000|" "$f"
  else
    echo "http_bind_address = 0.0.0.0:9000" >> "$f"
  fi
  if grep -q '^http_publish_uri\s*=' "$f"; then
    sed -i "s|^http_publish_uri\s*=.*|http_publish_uri = http://127.0.0.1:9000/|" "$f"
  else
    echo "http_publish_uri = http://127.0.0.1:9000/" >> "$f"
  fi

  # With Data Node, do NOT set opensearch/elasticsearch hosts here (auto-managed).
  # If you previously had elastic/opensearch hosts configured, comment them out:
  sed -i 's/^\s*\(elasticsearch_hosts\|opensearch_hosts\)\s*=.*$/# &/' "$f" || true

  systemctl daemon-reload
  systemctl enable graylog-server.service
  systemctl restart graylog-server.service
}

open_firewall() {
  # best-effort, only if tools exist
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

post_checks() {
  log "Services status (showing brief):"
  systemctl --no-pager --full status mongod | sed -n '1,5p' || true
  systemctl --no-pager --full status graylog-datanode | sed -n '1,5p' || true
  systemctl --no-pager --full status graylog-server | sed -n '1,10p' || true

  HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "${HOST_IP}" ]] && HOST_IP="127.0.0.1"

  echo
  echo "========================================================="
  echo " Graylog is (re)starting — first boot may take ~1–3 mins."
  echo
  echo " UI:        http://${HOST_IP}:9000/"
  echo " Login:     admin / admin   (CHANGE THIS ASAP)"
  echo "========================================================="
}

# ---------- Execute ----------
if [[ "$PM" == "apt" ]]; then
  log "Using APT flow"
  install_mongodb_apt
  install_graylog_stack_apt
elif [[ "$PM" == "dnf" ]]; then
  log "Using DNF flow"
  install_mongodb_rpm
  install_graylog_stack_rpm
fi

configure_datanode
configure_server
open_firewall
post_checks

log "Done."
