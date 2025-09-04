#!/usr/bin/env bash
# Graylog (Server + Data Node) + MongoDB installer/upgrader
# + Optional data disk auto-setup -> /gldata for indexes
# Ubuntu 22.04/24.04 or RHEL 8/9
# Terraform-friendly: logs to /var/log/server_install.log and ALWAYS exits 0

set -uo pipefail

# ---------------- Logging ----------------
LOG_FILE="/var/log/server_install.log"
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
chmod 0644 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

ERROR_COUNT=0
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
err()  { echo -e "\e[1;31m[x]\e[0m $*"; }
run()  { "$@" || { warn "Command failed (ignored): $*"; ERROR_COUNT=$((ERROR_COUNT+1)); return 0; }; }

if [[ $EUID -ne 0 ]]; then
  err "This script should run as root. Continuing, but operations may fail."
  ERROR_COUNT=$((ERROR_COUNT+1))
fi

# ---------------- Detect OS ----------------
source /etc/os-release 2>/dev/null || true
ID_LIKE="${ID_LIKE:-}"
OS="${ID:-unknown}"
VER_ID="${VERSION_ID:-unknown}"
log "Detected OS: ${PRETTY_NAME:-$OS $VER_ID}"

if [[ "$OS" == "ubuntu" ]] || [[ "$ID_LIKE" == *"debian"* ]]; then
  PM="apt"; export DEBIAN_FRONTEND=noninteractive
elif [[ "$OS" == "rhel" ]] || [[ "$ID_LIKE" == *"rhel"* ]] || [[ "$ID_LIKE" == *"fedora"* ]] || [[ "$ID_LIKE" == *"centos"* ]]; then
  PM="dnf"
else
  warn "Unsupported distribution: ${PRETTY_NAME:-$OS}. Trying APT path."
  PM="apt"; export DEBIAN_FRONTEND=noninteractive
fi

# ---------------- Constants ----------------
GL_REPO_BASE="https://packages.graylog2.org/repo/packages"
GL_MAJORS=(6.3 6.2 6.1 6.0 5.2 5.1 5.0)     # try newest first
MONGO_MAJOR_UBU="8.0"
MONGO_MAJOR_RHEL="8.0"                       # fallback to 7.0 if needed
ADMIN_SHA256="$(printf '%s' admin | sha256sum | awk '{print $1}')"
SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-false}"

# Threshold: 128 GiB in bytes
THRESHOLD_BYTES=$((128 * 1024 * 1024 * 1024))

# ---------------- Helpers ----------------
file_set_kv() {
  # file_set_kv <file> <key> <value>   (robust, no blank writes)
  local f="$1" k="$2" v="$3"
  [[ -f "$f" ]] || : > "$f"
  if grep -qE "^[[:space:]#]*${k}[[:space:]]*=" "$f" 2>/dev/null; then
    awk -v k="$k" -v v="$v" '
      BEGIN{ FS="="; OFS=" = " }
      $0 ~ "^[[:space:]#]*"k"[[:space:]]*=" { print k, v; next }
      { print }
    ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
  else
    printf "%s = %s\n" "$k" "$v" >> "$f"
  fi
}

get_host_ip() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  [[ -z "$ip" ]] && ip="$(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="127.0.0.1"
  echo "$ip"
}

root_disk() {
  # returns the disk name (e.g. sda or nvme0n1) backing /
  local src pk
  src="$(findmnt -n -o SOURCE / || true)"
  [[ -z "$src" ]] && return 1
  pk="$(lsblk -no PKNAME "$src" 2>/dev/null | head -n1)"
  [[ -z "$pk" ]] && pk="$(basename "$src" | sed 's/[0-9p]*$//')"
  echo "$pk"
}

# ---------------- Repos ----------------
add_graylog_repo_apt() {
  for ver in "${GL_MAJORS[@]}"; do
    local pkg="graylog-${ver}-repository_latest.deb"
    local url="${GL_REPO_BASE}/${pkg}"
    if curl -fsIL "$url" >/dev/null 2>&1; then
      log "Adding Graylog APT repo ($ver)"
      run curl -fsSL "$url" -o "/tmp/${pkg}"
      run dpkg -i "/tmp/${pkg}"
      return 0
    fi
  done
  warn "No Graylog APT repo package found."
  ERROR_COUNT=$((ERROR_COUNT+1))
}

add_graylog_repo_rpm() {
  for ver in "${GL_MAJORS[@]}"; do
    local pkg="graylog-${ver}-repository_latest.rpm"
    local url="${GL_REPO_BASE}/${pkg}"
    if curl -fsIL "$url" >/dev/null 2>&1; then
      log "Adding Graylog RPM repo ($ver)"
      run rpm -Uvh "$url"
      return 0
    fi
  done
  warn "No Graylog RPM repo package found."
  ERROR_COUNT=$((ERROR_COUNT+1))
}

# ---------------- MongoDB ----------------
install_mongodb_apt() {
  log "Installing MongoDB ${MONGO_MAJOR_UBU} (Ubuntu)"
  run apt-get update -y
  run apt-get install -y gnupg curl ca-certificates lsb-release
  run bash -c "curl -fsSL https://www.mongodb.org/static/pgp/server-${MONGO_MAJOR_UBU}.asc \
       | gpg --dearmor -o /usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg"
  local codename; codename=$(. /etc/os-release; echo "$VERSION_CODENAME")
  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-${MONGO_MAJOR_UBU}.gpg] https://repo.mongodb.org/apt/ubuntu ${codename}/mongodb-org/${MONGO_MAJOR_UBU} multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-${MONGO_MAJOR_UBU}.list
  run apt-get update -y
  run apt-get install -y mongodb-org
  run systemctl enable --now mongod
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
    run dnf clean all -y
    run dnf -y install mongodb-org
  fi
  run systemctl enable --now mongod
}

# ---------------- Disk tools ----------------
install_disk_utils() {
  if [[ "$PM" == "apt" ]]; then
    run apt-get install -y xfsprogs parted
  else
    run dnf -y install xfsprogs parted
  fi
}

# ---------------- Graylog packages ----------------
install_graylog_stack_apt() {
  add_graylog_repo_apt
  run apt-get update -y
  run apt-get install -y openjdk-17-jre-headless || run apt-get install -y openjdk-11-jre-headless
  run apt-get install -y graylog-datanode graylog-server
}

install_graylog_stack_rpm() {
  add_graylog_repo_rpm
  run dnf -y install java-17-openjdk || run dnf -y install java-11-openjdk
  run dnf -y install graylog-datanode graylog-server
}

# ---------------- Prepare /gldata (auto-disk initialisation if possible) ----------------
prepare_gldata_mount() {
  log "Preparing /gldata target for Data Node indexes…"
  mkdir -p /gldata

  # If already a mountpoint, we're done
  if mountpoint -q /gldata; then
    log "/gldata already mounted."
    return 0
  fi

  install_disk_utils

  local rootd dev size part partdev uuid
  rootd="$(root_disk)"

  # Find eligible uninitialised disks (>128GiB), prefer the largest
  local best_dev="" best_size=0
  while read -r name type; do
    [[ "$type" != "disk" ]] && continue
    [[ "$name" == "$rootd" ]] && continue
    [[ "$name" =~ ^(loop|sr|zd|dm-) ]] && continue

    dev="/dev/$name"
    # Skip if it has partitions
    if lsblk -n "$dev" 2>/dev/null | awk 'NR>1{exit 0} END{exit 1}'; then
      # has children -> skip
      continue
    fi
    # Skip if it already has a filesystem
    if lsblk -no FSTYPE "$dev" 2>/dev/null | grep -q .; then
      continue
    fi
    size=$(blockdev --getsize64 "$dev" 2>/dev/null || echo 0)
    [[ -z "$size" ]] && size=0
    if (( size > THRESHOLD_BYTES )) && (( size > best_size )); then
      best_size=$size
      best_dev="$dev"
    fi
  done < <(lsblk -dn -o NAME,TYPE)

  if [[ -z "$best_dev" ]]; then
    warn "No uninitialised disk > 128GiB found. Using root filesystem for /gldata."
    return 0
  fi

  log "Initialising $best_dev ($(numfmt --to=iec --suffix=B "$best_size" 2>/dev/null || echo "$best_size bytes")) for /gldata…"
  # Partition -> single GPT partition
  run parted -s "$best_dev" mklabel gpt
  run parted -s "$best_dev" mkpart primary xfs 1MiB 100%
  # Determine created partition name (handles nvmeXn1p1)
  part="$(lsblk -ln "$best_dev" -o NAME | awk 'NR==2{print $1}')"
  partdev="/dev/${part:-${best_dev#'/dev/'}1}"
  # Create filesystem (XFS preferred, fallback ext4)
  if command -v mkfs.xfs >/dev/null 2>&1; then
    run mkfs.xfs -f "$partdev"
    fstype="xfs"
    fsopts="defaults,nofail"
  else
    run mkfs.ext4 -F "$partdev"
    fstype="ext4"
    fsopts="defaults,nofail"
  fi

  # Get UUID and persist in fstab
  uuid="$(blkid -s UUID -o value "$partdev" 2>/dev/null || true)"
  if [[ -n "$uuid" ]]; then
    echo "UUID=$uuid /gldata $fstype $fsopts 0 2" >> /etc/fstab
  else
    warn "Could not determine UUID for $partdev; writing fstab with device path."
    echo "$partdev /gldata $fstype $fsopts 0 2" >> /etc/fstab
  fi

  # Mount
  run systemctl daemon-reload
  run mount -a
  if mountpoint -q /gldata; then
    log "/gldata mounted successfully."
  else
    warn "Failed to mount /gldata; continuing on root filesystem."
  fi
}

# ---------------- Graylog Server config ----------------
PASSWORD_SECRET=""
configure_graylog_server() {
  local conf="/etc/graylog/server/server.conf"
  log "Configuring graylog-server: $conf"
  mkdir -p /etc/graylog/server
  [[ -f "$conf" ]] || run cp /usr/share/graylog-server/server.conf "$conf"

  # Derive or generate a non-blank shared secret
  PASSWORD_SECRET="$(awk -F= '/^[[:space:]]*password_secret[[:space:]]*=/{s=$2} END{gsub(/^[ \t]+|[ \t]+$/, "", s); print s}' "$conf" 2>/dev/null || true)"
  if [[ -z "$PASSWORD_SECRET" ]]; then
    if command -v openssl >/dev/null 2>&1; then
      PASSWORD_SECRET="$(openssl rand -base64 96 | tr -d '\n')"
    else
      PASSWORD_SECRET="$(head -c 96 /dev/urandom | base64 | tr -d '\n')"
    fi
  fi
  file_set_kv "$conf" "password_secret" "$PASSWORD_SECRET"

  # Admin: admin/admin and basics
  file_set_kv "$conf" "root_password_sha2" "$ADMIN_SHA256"
  file_set_kv "$conf" "is_master" "true"
  file_set_kv "$conf" "root_email" "admin@example.org"
  file_set_kv "$conf" "root_timezone" "UTC"
  file_set_kv "$conf" "http_bind_address" "0.0.0.0:9000"
  file_set_kv "$conf" "http_publish_uri" "http://127.0.0.1:9000/"

  # Don’t point to external OpenSearch when using Data Node
  sed -i 's/^\s*\(elasticsearch_hosts\|opensearch_hosts\)\s*=.*$/# &/' "$conf" || true

  run systemctl daemon-reload
  run systemctl enable graylog-server.service
}

# ---------------- Graylog Data Node config ----------------
configure_datanode() {
  local conf="/etc/graylog/datanode/datanode.conf"
  log "Configuring graylog-datanode: $conf"
  mkdir -p /etc/graylog/datanode
  [[ -f "$conf" ]] || : > "$conf"
  cp -a "$conf" "${conf}.bak.$(date +%s)" || true

  local ip; ip="$(get_host_ip)"

  # Ensure /gldata path exists for data + logs
  mkdir -p /gldata/opensearch/data /gldata/opensearch/logs
  # Best-effort ownership for both possible service users
  for u in graylog graylog-datanode; do
    id "$u" >/dev/null 2>&1 && run chown -R "$u":"$u" /gldata/opensearch || true
  done

  # Required ports/binds + shared secret + Mongo + DATA PATHS
  file_set_kv "$conf" "bind_address" "0.0.0.0"
  file_set_kv "$conf" "datanode_http_port" "8999"
  file_set_kv "$conf" "http_publish_uri" "http://${ip}:8999/"
  file_set_kv "$conf" "opensearch_http_port" "9200"
  file_set_kv "$conf" "opensearch_transport_port" "9300"
  file_set_kv "$conf" "opensearch_network_host" "0.0.0.0"
  file_set_kv "$conf" "mongodb_uri" "mongodb://127.0.0.1:27017/graylog"
  file_set_kv "$conf" "password_secret" "$PASSWORD_SECRET"

  # Place indexes and OpenSearch logs on /gldata
  file_set_kv "$conf" "opensearch_data_location" "/gldata/opensearch/data"
  file_set_kv "$conf" "opensearch_logs_location" "/gldata/opensearch/logs"

  # Optional lab-only: bypass preflight wizard
  if [[ "${SKIP_PREFLIGHT,,}" == "true" ]]; then
    file_set_kv "$conf" "skip_preflight_checks" "true"
  fi

  # Heap heuristic (cap 8g)
  if ! grep -q '^opensearch_heap' "$conf" 2>/dev/null; then
    if [[ -r /proc/meminfo ]]; then
      local mem_kb half_gb
      mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
      half_gb=$(( (mem_kb/1024/1024)/2 ))
      (( half_gb < 1 )) && half_gb=1
      (( half_gb > 8 )) && half_gb=8
      echo "opensearch_heap = ${half_gb}g" >> "$conf"
    else
      echo "opensearch_heap = 2g" >> "$conf"
    fi
  fi

  # Kernel and systemd prerequisites for OpenSearch
  echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-graylog.conf
  run sysctl --system

  mkdir -p /etc/systemd/system/graylog-datanode.service.d
  cat > /etc/systemd/system/graylog-datanode.service.d/override.conf <<'EOF'
[Service]
LimitNOFILE=65536
LimitMEMLOCK=infinity
EOF

  run systemctl daemon-reload
  run systemctl enable graylog-datanode.service
}

# ---------------- Firewall (best-effort) ----------------
open_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    run ufw allow 9000/tcp
    run ufw allow 1514/tcp
    run ufw allow 1514/udp
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    run firewall-cmd --add-port=9000/tcp --permanent
    run firewall-cmd --add-port=1514/tcp --permanent
    run firewall-cmd --add-port=1514/udp --permanent
    run firewall-cmd --reload
  fi
}

# ---------------- Wait helpers (non-fatal) ----------------
wait_for_port() {
  local port="$1" timeout="${2:-420}"
  log "Waiting for TCP :$port (timeout ${timeout}s)…"
  for ((i=0;i<timeout;i++)); do
    ss -ltn 2>/dev/null | grep -q ":${port} " && { log "Port :$port is listening."; return 0; }
    sleep 1
  done
  warn "Timeout waiting for port :$port"
  ERROR_COUNT=$((ERROR_COUNT+1))
  return 0
}

dump_brief_logs() {
  echo "----- journalctl graylog-datanode (tail) -----"
  journalctl -u graylog-datanode -n 80 --no-pager 2>/dev/null || true
  echo "----- datanode.log (tail) -----"
  tail -n 120 /var/log/graylog-datanode/datanode.log 2>/dev/null || true
  echo "----- opensearch.log (tail) -----"
  tail -n 120 /var/log/graylog-datanode/opensearch.log 2>/dev/null || true
  echo "----- server.log (preflight creds, if any) -----"
  grep -iE 'preflight|temporary|credential|username|password' /var/log/graylog-server/server.log 2>/dev/null | tail -n 40 || true
}

show_preflight_credentials() {
  echo
  echo "================ Preflight credentials (if present) ================"
  if [[ -f /var/log/graylog-server/server.log ]]; then
    tail -n 300 /var/log/graylog-server/server.log \
      | grep -iE 'preflight|temporary|credential|username|password' \
      | tail -n 60 || true
    echo "----- journalctl graylog-server (filtered tail) -----"
    journalctl -u graylog-server -n 200 --no-pager 2>/dev/null \
      | grep -iE 'preflight|temporary|credential|username|password' \
      | tail -n 60 || true
  else
    echo "server.log not found at /var/log/graylog-server/server.log"
  fi
  echo "===================================================================="
  echo
}

# ---------------- Execute ----------------
# (1) Base packages
if [[ "$PM" == "apt" ]]; then
  log "Using APT flow"
  run apt-get update -y
  install_mongodb_apt
  install_graylog_stack_apt
else
  log "Using DNF flow"
  install_mongodb_rpm
  install_graylog_stack_rpm
fi

# (2) Data disk -> /gldata (must happen BEFORE datanode config/start)
prepare_gldata_mount

# (3) Configure Graylog
configure_graylog_server
configure_datanode
open_firewall

# (4) Start/restart (non-fatal) and waits
run systemctl restart graylog-datanode
run systemctl restart graylog-server

wait_for_port 8999 420   # Data Node REST
wait_for_port 9200 420   # OpenSearch REST
wait_for_port 9000 300   # Graylog UI

# Dump tails if any warnings happened
if [[ $ERROR_COUNT -gt 0 ]]; then
  dump_brief_logs
fi

# ---------------- Summary ----------------
HOST_IP="$(get_host_ip)"
log "Services status (brief):"
run systemctl --no-pager --full status mongod | sed -n '1,6p'
run systemctl --no-pager --full status graylog-datanode | sed -n '1,8p'
run systemctl --no-pager --full status graylog-server | sed -n '1,10p'

cat <<EOF

=========================================================
 Graylog install/upgrade finished (with ${ERROR_COUNT} warning(s)).

 UI:        http://${HOST_IP}:9000/
 Login:     admin / admin   (CHANGE IMMEDIATELY)
 Logs:      ${LOG_FILE}
 Data:      /gldata/opensearch/data  (indexes)
=========================================================

EOF

# Print preflight credentials (best-effort)
show_preflight_credentials

# Always exit 0 for Terraform
exit 0
