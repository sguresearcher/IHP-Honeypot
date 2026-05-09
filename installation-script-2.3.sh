#!/bin/bash
# ============================================================
# HONEYPOT INSTALLER v2.3
# Idempotent — safe to run multiple times
# Fix: URL-encode NATS password, dionaea volume, remove -it flag
# Fix: cleanup old containers by port (random Docker names)
# + TLS support for connection to NATS Hub (CA cert)
# + Malware Uploader (dionaea binaries → NATS JetStream Object Store)
# ============================================================

set -euo pipefail

BANNER='
   __ __                                 __    ____           __         __ __
  / // /___   ___  ___  __ __ ___  ___  / /_  /  _/___   ___ / /_ ___ _ / // /___  ____
 / _  // _ \ / _ \/ -_)/ // // _ \/ _ \/ __/ _/ / / _ \ (_-</ __// _  // // // -_)/ __/
/_//_/ \___//_//_/\__/ \_, // .__/\___/\__/ /___//_//_//___/\__/ \_,_//_//_/ \__//_/
                      /___//_/
             Honeypot Installer v2.3 — TLS Edition
'
echo "$BANNER"

# ============================================================
# HELPERS
# ============================================================

log()    { echo "[+] $*"; }
warn()   { echo "[!] $*"; }
info()   { echo "[-] $*"; }
die()    { echo "[✗] $*" >&2; exit 1; }

# URL-encode a string (RFC 3986)
urlencode() {
    local raw="$1"
    local encoded=""
    local i char
    for (( i=0; i<${#raw}; i++ )); do
        char="${raw:$i:1}"
        case "$char" in
            [A-Za-z0-9\-_.~]) encoded+="$char" ;;
            *) encoded+=$(printf '%%%02X' "'$char") ;;
        esac
    done
    echo "$encoded"
}

container_exists()  { sudo docker ps -a --format '{{.Names}}' | grep -qx "$1"; }
container_running() { sudo docker ps    --format '{{.Names}}' | grep -qx "$1"; }

# Free a port: stop Docker containers AND host processes binding that port
# free_port() {
#     local port="$1"

#     # 1) Docker containers publishing this port
#     local ids
#     ids=$(sudo docker ps -q --filter "publish=${port}" 2>/dev/null || true)
#     if [[ -n "$ids" ]]; then
#         warn "  Docker: port ${port} is used by a container — stopping..."
#         echo "$ids" | xargs sudo docker rm -f 2>/dev/null || true
#     fi

#     # 2) Host processes (nginx, apache, etc.) listening on this port
#     if sudo ss -tlnup 2>/dev/null | grep -q ":${port} "; then
#         warn "  Host: port ${port} is used by a host process — killing..."
#         sudo fuser -k "${port}/tcp" 2>/dev/null || true
#         sudo fuser -k "${port}/udp" 2>/dev/null || true
#     fi
# }

# Protect critical ports (SSH etc.)
PROTECTED_PORTS=(22888)

free_port() {
    local port="$1"

    # 🔒 Skip protected ports
    for p in "${PROTECTED_PORTS[@]}"; do
        if [[ "$port" == "$p" ]]; then
            warn "Skipping protected port $port"
            return
        fi
    done

    # 1) Docker containers publishing this port
    local ids
    ids=$(sudo docker ps -q --filter "publish=${port}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        warn "  Docker: port ${port} is used by a container — stopping..."
        echo "$ids" | xargs sudo docker rm -f 2>/dev/null || true
    fi

    # 2) Host processes using this port
    if sudo ss -tlnup 2>/dev/null | grep -q ":${port} "; then
        warn "  Host: port ${port} is used by a host process — killing..."
        sudo fuser -k "${port}/tcp" 2>/dev/null || true
        sudo fuser -k "${port}/udp" 2>/dev/null || true
    fi
}

free_ports() {
    log "Freeing ports: $*"
    for p in "$@"; do
        free_port "$p"
    done
    sleep 1   # give the kernel time to release the socket
}

# ============================================================
# PREFLIGHT CHECKS
# ============================================================

read -p "Do you accept the terms and conditions? (y/n) " -r
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    die "Do not run as root. Use a regular user with sudo."
fi

sudo -l &>/dev/null || die "User must have sudo permissions."

# ============================================================
# FORCE PHASE CONTROL
# ============================================================

FORCE_PHASE1=false

if [[ "${1:-}" == "--phase1" ]]; then
    FORCE_PHASE1=true
    warn "Forcing Phase 1 execution (manual override)."
fi

# ============================================================
# CONFIGURATION INPUT
# ============================================================

ENV_CACHE="/var/honeypot_env.cache"
USE_CACHE=false

if [ -f "$ENV_CACHE" ]; then
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║   Previous Configuration Found       ║"
    echo "╚══════════════════════════════════════╝"
    read -p "Use previous configuration? [Y/n, default: Y]: " REUSE_ENV
    REUSE_ENV=${REUSE_ENV:-"Y"}
    if [[ "$REUSE_ENV" =~ ^[Yy]$ ]]; then
        if [ -r "$ENV_CACHE" ]; then
            source "$ENV_CACHE"
        else
            warn "Cannot read $ENV_CACHE — permission issue"
        fi
        USE_CACHE=true
        LEAF_CREDS_CONTENT=$(echo "$LEAF_CREDS_B64" | base64 -d)
        if [ "$NATS_TLS_ENABLED" = "true" ]; then
            TLS_CA_CONTENT=$(echo "$TLS_CA_B64" | base64 -d)
        fi
        log "Previous configuration successfully loaded from $ENV_CACHE."
    fi
fi

if [ "$USE_CACHE" = false ]; then

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      NATS Hub Configuration          ║"
echo "╚══════════════════════════════════════╝"
read -p "NATS Hub IPs (comma-separated) [default: 103.19.110.157]: " NATS_HOSTS
NATS_HOSTS=${NATS_HOSTS:-"103.19.110.157"}
read -p "NATS Hub Port [default: 4222]: " NATS_PORT
NATS_PORT=${NATS_PORT:-"4222"}
LEAF_CREDS_CONTENT=""
echo ""
echo "╔══════════════════════════════════════╗"
echo "║      NATS JWT Credentials            ║"
echo "╚══════════════════════════════════════╝"
echo "    Please COPY the entire contents of this Tenant's credentials (.creds) file."
echo "    Then PASTE it in this terminal. Once all text is pasted, type 'EOF' on a new line and press Enter:"
echo "    --------------------------------------------------------"

while IFS= read -r line; do
  if [[ "$line" == "EOF" ]]; then
    break
  fi
  LEAF_CREDS_CONTENT+="$line"$'\n'
done

if [[ -z "$(echo -n "$LEAF_CREDS_CONTENT" | tr -d '[:space:]')" ]]; then
  die "Credentials must not be empty!"
fi
echo "    --------------------------------------------------------"
log "Credentials successfully read."

# ============================================================
# INPUT TLS CONFIGURATION
# ============================================================

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      TLS Configuration               ║"
echo "╚══════════════════════════════════════╝"
echo "    TLS encrypts the connection between the leaf node and the NATS Hub."
echo "    You need the CA certificate from the NATS Hub server."
echo ""
read -p "Enable TLS to NATS Hub? [Y/n, default: Y]: " USE_TLS
USE_TLS=${USE_TLS:-"Y"}

NATS_TLS_ENABLED=false
TLS_CA_CONTENT=""
TLS_SKIP_VERIFY=false
NATS_URL_SCHEME="nats"

if [[ "$USE_TLS" =~ ^[Yy]$ ]]; then
    NATS_TLS_ENABLED=true
    NATS_URL_SCHEME="tls"

    echo ""
    echo "[?] CA Certificate Source"
    echo "    [1] Paste CA cert contents directly (inline)"
    echo "    [2] Provide path to an existing CA cert file"
    read -p "    Choose [1/2, default: 1]: " TLS_CERT_CHOICE
    TLS_CERT_CHOICE=${TLS_CERT_CHOICE:-"1"}

    if [[ "$TLS_CERT_CHOICE" == "2" ]]; then
        read -p "    CA cert file path (.pem): " CA_CERT_PATH
        [[ -f "$CA_CERT_PATH" ]] || die "CA cert file not found: ${CA_CERT_PATH}"
        TLS_CA_CONTENT=$(cat "$CA_CERT_PATH")
        log "CA cert read from: ${CA_CERT_PATH}"
    else
        echo ""
        echo "    Please PASTE the CA certificate (.pem) contents below."
        echo "    When done, type 'EOF' on a new line and press Enter:"
        echo "    --------------------------------------------------------"
        while IFS= read -r line; do
            if [[ "$line" == "EOF" ]]; then
                break
            fi
            TLS_CA_CONTENT+="$line"$'\n'
        done
        echo "    --------------------------------------------------------"

        if [[ -z "$(echo -n "$TLS_CA_CONTENT" | tr -d '[:space:]')" ]]; then
            die "CA certificate must not be empty!"
        fi
        log "CA cert successfully read (inline)."
    fi

    echo ""
    read -p "    Skip TLS verification (not recommended, for dev only)? [y/N, default: N]: " TLS_SKIP_INPUT
    TLS_SKIP_INPUT=${TLS_SKIP_INPUT:-"N"}
    if [[ "$TLS_SKIP_INPUT" =~ ^[Yy]$ ]]; then
        TLS_SKIP_VERIFY=true
        warn "TLS verification disabled (insecure_skip_verify). For testing only!"
    fi

    log "TLS enabled (URL scheme: ${NATS_URL_SCHEME}://)."
else
    log "TLS disabled. Plain connection without encryption."
fi



# ============================================================
# ZABBIX CONFIGURATION
# ============================================================

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      Zabbix Configuration            ║"
echo "╚══════════════════════════════════════╝"
read -p "Zabbix Hostname (name of this VM): " ZABBIX_HOSTNAME
[[ -n "$ZABBIX_HOSTNAME" ]] || die "Zabbix hostname must not be empty."

    # Save to cache
    sudo touch "$ENV_CACHE"
    sudo chown "$USER":"$USER" "$ENV_CACHE"
    chmod 600 "$ENV_CACHE"
    cat <<EOF | sudo tee "$ENV_CACHE" >/dev/null
NATS_HOSTS="${NATS_HOSTS}"
NATS_PORT="${NATS_PORT}"
USE_TLS="${USE_TLS}"
NATS_TLS_ENABLED="${NATS_TLS_ENABLED}"
NATS_URL_SCHEME="${NATS_URL_SCHEME}"
TLS_SKIP_VERIFY="${TLS_SKIP_VERIFY}"
ZABBIX_HOSTNAME="${ZABBIX_HOSTNAME}"
LEAF_CREDS_B64="$(echo "$LEAF_CREDS_CONTENT" | base64 -w 0)"
EOF
    if [ "$NATS_TLS_ENABLED" = "true" ]; then
        echo "TLS_CA_B64=\"$(echo "$TLS_CA_CONTENT" | base64 -w 0)\"" | sudo tee -a "$ENV_CACHE" >/dev/null
    fi
    log "New configuration saved to $ENV_CACHE."

fi # end USE_CACHE = false

# ============================================================
# AUTO VM ID
# ============================================================

HOSTNAME_ID=$(hostname | tr '[:upper:]' '[:lower:]')
IP_SUFFIX=$(curl -s --max-time 5 ifconfig.me 2>/dev/null | awk -F. '{print $4}')
IP_SUFFIX=${IP_SUFFIX:-"unknown"}
VM_ID="${HOSTNAME_ID}-${IP_SUFFIX}"
log "VM_ID: ${VM_ID}"

# ============================================================
# FLAG FILE — two-phase install (reboot boundary)
# ============================================================

FLAG_FILE="/var/honeypot_install_flag"

phase1_done() { [ -f "$FLAG_FILE" ]; }

# ============================================================
# PHASE 1 — Pre-reboot setup
# ============================================================

if ! phase1_done || $FORCE_PHASE1; then
    log "PHASE 1: System preparation..."

    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
        -o Dpkg::Options::="--force-confnew"

    # --- Limits ---
    LIMITS_CONF="/etc/security/limits.conf"
    for line in \
        "root soft nofile 65536" \
        "root hard nofile 65536" \
        "* soft nofile 65536" \
        "* hard nofile 65536"; do
        grep -qF "$line" "$LIMITS_CONF" || echo "$line" | sudo tee -a "$LIMITS_CONF" >/dev/null
    done

    # --- Sysctl ---
    SYSCTL_CONF="/etc/sysctl.conf"
    declare -A SYSCTL_MAP=(
        ["net.core.somaxconn"]="1024"
        ["net.core.netdev_max_backlog"]="5000"
        ["net.core.rmem_max"]="16777216"
        ["net.core.wmem_max"]="16777216"
    )
    for key in "${!SYSCTL_MAP[@]}"; do
        val="${SYSCTL_MAP[$key]}"
        if grep -q "^${key}" "$SYSCTL_CONF"; then
            sudo sed -i "/^${key}/c\\${key} = ${val}" "$SYSCTL_CONF"
        else
            echo "${key} = ${val}" | sudo tee -a "$SYSCTL_CONF" >/dev/null
        fi
    done
    sudo sysctl -p

    # --- Swap ---
    if ! swapon --show | grep -q /swapfile; then
        sudo fallocate -l 1G /swapfile
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        grep -qF '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        log "1G Swap is active."
    else
        info "Swap already exists, skipping."
    fi

    sudo touch "$FLAG_FILE"
    log "PHASE 1 complete. Reboot required..."
    read -p "Reboot now? (y/n) " -r
    [[ $REPLY =~ ^[Yy]$ ]] || { warn "Re-run the script after manual reboot."; exit 0; }
    sudo reboot
    exit 0
fi

# ============================================================
# PHASE 2 — Post-reboot: Docker + Honeypots + NATS + Fluent Bit
# ============================================================

log "PHASE 2: Installing Docker and Honeypot containers..."

# Ensure port-management tools are available
sudo apt-get install -y psmisc iproute2 &>/dev/null || true

# ============================================================
# DOCKER
# ============================================================

if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo groupadd docker 2>/dev/null || true
    sudo usermod -aG docker "$USER"
    sudo systemctl enable docker.service containerd.service
    log "Docker installed."
else
    info "Docker already present ($(docker --version)), skipping install."
fi

# Ensure the current user can access docker without sudo in this session
if ! groups | grep -q docker; then
    warn "User is not in the docker group. Use sudo or re-login."
fi

# ============================================================
# INSECURE REGISTRY
# ============================================================

REGISTRY_IP="103.19.110.148:5000"
DAEMON_JSON="/etc/docker/daemon.json"

if ! grep -q "$REGISTRY_IP" "$DAEMON_JSON" 2>/dev/null; then
    log "Adding insecure registry..."
    echo "{ \"insecure-registries\":[\"${REGISTRY_IP}\"] }" | sudo tee "$DAEMON_JSON"
    sudo systemctl restart docker
else
    info "Insecure registry already configured, skipping."
fi

# ============================================================
# SSH PORT CHANGE
# ============================================================

NEW_SSH_PORT="22888"
CURRENT_SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")

if [ "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]; then
    warn "SSH port will be changed to ${NEW_SSH_PORT}. Make sure that port is open in the firewall!"
    read -p "Continue? (y/n) " -r
    [[ $REPLY =~ ^[Yy]$ ]] || die "Cancelled by user."
    sudo sed -i -e "s/^#\\?Port .*/Port ${NEW_SSH_PORT}/" /etc/ssh/sshd_config
    
    if command -v ufw &>/dev/null; then
        sudo ufw allow "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
        log "Port ${NEW_SSH_PORT}/tcp allowed in UFW."
    fi

    if command -v systemctl &>/dev/null; then
        if systemctl list-unit-files | grep -q sshd.service; then
            sudo systemctl restart sshd
        else
            sudo systemctl restart ssh
        fi
    else
        sudo service ssh restart
    fi
    log "SSH port changed to ${NEW_SSH_PORT}."
else
    info "SSH is already on port ${NEW_SSH_PORT}, skipping."
fi

# ============================================================
# PULL IMAGES
# ============================================================

IMAGES=(
    "cowrie" "conpot" "rdpy" "elasticpot" "dionaea" "honeytrap"
)

log "Pulling honeypot images..."
for img in "${IMAGES[@]}"; do
    if sudo docker image inspect "${REGISTRY_IP}/${img}:latest" &>/dev/null; then
        info "Image ${img} already exists, skipping pull."
    else
        log "Pulling ${img}..."
        sudo docker pull "${REGISTRY_IP}/${img}:latest"
    fi
done

# ============================================================
# VOLUMES
# ============================================================

VOLUMES=("cowrie-var" "cowrie-etc" "gridpot" "elasticpot" "dionaea" "honeytrap-data" "conpot-data")

log "Creating Docker volumes..."
for vol in "${VOLUMES[@]}"; do
    if sudo docker volume inspect "$vol" &>/dev/null; then
        info "Volume ${vol} already exists, skipping."
    else
        sudo docker volume create "$vol"
        log "Volume ${vol} created."
    fi
done

sudo mkdir -p /var/lib/docker/volumes/rdpy/_data

# ============================================================
# HONEYPOT CONTAINERS
# Idempotent: skip if container is already running, recreate if exited
# ============================================================

start_container() {
    local name="$1"
    shift
    if container_running "$name"; then
        info "Container ${name} is already running, skipping."
        return 0
    fi
    if container_exists "$name"; then
        warn "Container ${name} exists but is not running. Removing and recreating..."
        sudo docker rm -f "$name"
    fi
    log "Starting container ${name}..."
    sudo docker run --name "$name" "$@"
}

# Hardcoded container names for idempotency and easy identification
C_COWRIE="cowrie-hp"
C_DIONAEA="dionaea-hp"
C_RDPY="rdpy-hp"
C_ELASTICPOT="elasticpot-hp"
C_HONEYTRAP="honeytrap-hp"
C_CONPOT="conpot-hp"

# --- Cowrie ---
free_ports 22 23
start_container "$C_COWRIE" \
    -p 22:22/tcp -p 23:23/tcp \
    -v cowrie-etc:/cowrie/cowrie-git/etc \
    -v cowrie-var:/cowrie/cowrie-git/var \
    -d --cap-drop=ALL --cap-add=NET_BIND_SERVICE --read-only --restart unless-stopped \
    "${REGISTRY_IP}/cowrie:latest"

# --- Dionaea ---
free_ports 21 42 80 135 443 445 1433 1723 1883 3306 5060 5061 11211
start_container "$C_DIONAEA" \
    -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 \
    -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 \
    -p 1883:1883 -p 3306:3306 -p 5060:5060 -p 5060:5060/udp \
    -p 5061:5061 -p 11211:11211 \
    -v dionaea:/opt/dionaea \
    -d --restart unless-stopped \
    "${REGISTRY_IP}/dionaea:latest"

# --- RDPy ---
free_ports 3389
start_container "$C_RDPY" \
    -p 3389:3389 -v rdpy:/var/log \
    -d --restart unless-stopped \
    "${REGISTRY_IP}/rdpy:latest" \
    /bin/sh -c 'python /rdpy/bin/rdpy-rdphoneypot.py -l 3389 /rdpy/bin/1 >> /var/log/rdpy.log'

# --- Elasticpot ---
free_ports 9200
start_container "$C_ELASTICPOT" \
    -p 9200:9200/tcp -v elasticpot:/elasticpot/log \
    -d --restart unless-stopped \
    "${REGISTRY_IP}/elasticpot:latest" \
    /bin/sh -c 'cd elasticpot; python3 elasticpot.py'

# --- Honeytrap ---
free_ports 2222 8545 5900 25 5037 631 389 6379
start_container "$C_HONEYTRAP" \
    -p 2222:2222 -p 8545:8545 -p 5900:5900 -p 25:25 \
    -p 5037:5037 -p 631:631 -p 389:389 -p 6379:6379 \
    -v honeytrap-data:/home \
    -d --restart unless-stopped \
    "${REGISTRY_IP}/honeytrap:latest"

# --- Conpot ---
free_ports 8000 10201 5020 2121 44818
start_container "$C_CONPOT" \
    -v conpot-data:/data \
    -p 8000:8800 -p 10201:10201 -p 5020:5020 \
    -p 16100:16100/udp -p 47808:47808/udp -p 6230:6230/udp \
    -p 2121:2121 -p 6969:6969/udp -p 44818:44818 \
    -d --restart always \
    "${REGISTRY_IP}/conpot:latest"

# ============================================================
# NATS LEAF NODE
# ============================================================

NATS_DIR="/opt/nats-leaf"
sudo mkdir -p "${NATS_DIR}"
sudo mkdir -p "${NATS_DIR}/certs"
sudo mkdir -p "${NATS_DIR}/creds"

echo "$LEAF_CREDS_CONTENT" | sudo tee "${NATS_DIR}/creds/leafnode.creds" >/dev/null
sudo chmod 600 "${NATS_DIR}/creds/leafnode.creds"
log "Credentials saved to: ${NATS_DIR}/creds/leafnode.creds"

# ============================================================
# SAVE CA CERT (if TLS is enabled)
# ============================================================

TLS_BLOCK=""
NATS_CERTS_VOLUME_ARG=""

if [[ "$NATS_TLS_ENABLED" == "true" ]]; then
    echo "$TLS_CA_CONTENT" | sudo tee "${NATS_DIR}/certs/ca.pem" >/dev/null
    sudo chmod 644 "${NATS_DIR}/certs/ca.pem"
    log "CA cert saved to: ${NATS_DIR}/certs/ca.pem"

    # TLS block for NATS leaf config
    if [[ "$TLS_SKIP_VERIFY" == "true" ]]; then
        TLS_BLOCK='
      tls {
        insecure: true
      }'
    else
        TLS_BLOCK='
      tls {
        ca_file: "/certs/ca.pem"
      }'
    fi

    NATS_CERTS_VOLUME_ARG="-v ${NATS_DIR}/certs:/certs:ro"
fi

# Build leaf remotes from comma-separated IPs
LEAF_REMOTES=""
IFS=',' read -ra HOSTS <<< "$NATS_HOSTS"
for host in "${HOSTS[@]}"; do
    cleaned_host=$(echo "$host" | tr -d ' ')
    LEAF_REMOTES="${LEAF_REMOTES}
    {
      url: \"${NATS_URL_SCHEME}://${cleaned_host}:${NATS_PORT}\"
      credentials: \"/creds/leafnode.creds\"${TLS_BLOCK}
    }"
done

# Write config (always re-generate so the latest credentials are always used)
sudo tee "${NATS_DIR}/nats-leaf.conf" > /dev/null <<LEAFEOF
# NATS Leaf Node — Honeypot VM: ${VM_ID}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# TLS Enabled: ${NATS_TLS_ENABLED}

server_name: "honeypot-leaf-${VM_ID}"

listen: 0.0.0.0:4222
http: 0.0.0.0:8222

max_payload: 524288
max_connections: 100
write_deadline: "3s"
jetstream: true

leafnodes {
  remotes [${LEAF_REMOTES}
  ]
}

debug: false
trace: false
logtime: true
LEAFEOF

log "NATS leaf config written to: ${NATS_DIR}/nats-leaf.conf"
if [[ "$NATS_TLS_ENABLED" == "true" ]]; then
    log "NATS URL scheme: ${NATS_URL_SCHEME}:// (TLS encrypted)"
    log "CA cert mounted into container at: /certs/ca.pem"
fi

# Idempotent: remove old container if config changed or not running
if container_exists "nats-leaf"; then
    warn "Container nats-leaf already exists. Recreating with latest config..."
    sudo docker rm -f nats-leaf
fi

log "Starting NATS Leaf Node.."
sudo docker run -d \
    --name nats-leaf \
    --restart unless-stopped \
    -p 127.0.0.1:4222:4222 \
    -p 127.0.0.1:8222:8222 \
    -v "${NATS_DIR}/nats-leaf.conf:/etc/nats/nats.conf:ro" \
    -v "${NATS_DIR}/creds/leafnode.creds:/creds/leafnode.creds:ro" \
    ${NATS_CERTS_VOLUME_ARG} \
    --health-cmd='wget -q --spider http://localhost:8222/healthz || exit 1' \
    --health-interval=10s \
    --health-timeout=3s \
    --health-retries=3 \
    nats:2.10-alpine \
    -c /etc/nats/nats.conf

log "NATS Leaf Node started. Waiting for connection to hub..."
sleep 5
NATS_LEAF_STATUS=$(sudo docker logs nats-leaf 2>&1 | tail -5)
echo "$NATS_LEAF_STATUS"

# ============================================================
# FLUENT BIT
# ============================================================

FB_DIR="/opt/fluent-bit-hp"
sudo mkdir -p "${FB_DIR}/state"

# parsers.conf
sudo tee "${FB_DIR}/parsers.conf" > /dev/null <<'EOF'
[PARSER]
    Name        cowrie_json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ

[PARSER]
    Name        dionaea_json
    Format      json

[PARSER]
    Name        conpot_json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%L

[PARSER]
    Name        elasticpot_json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S

[PARSER]
    Name        honeytrap_json
    Format      json
    Time_Key    date
    Time_Format %Y-%m-%dT%H:%M:%S.%L
EOF

# Lua reformat timestamp
sudo tee "${FB_DIR}/reformat-timestamp.lua" > /dev/null << 'EOF'
function reformat_timestamp(tag, timestamp, record)
    local s = os.date("!%Y-%m-%d %H:%M:%S", timestamp)
    local ms = string.format(".%03u", math.floor((timestamp % 1) * 1000))
    record["timestamp"] = s .. ms
    return 1, timestamp, record
end
EOF

# fluent-bit.conf
sudo tee "${FB_DIR}/fluent-bit.conf" > /dev/null <<FBEOF
[SERVICE]
    Flush                        1
    Log_Level                    info
    Parsers_File                 /fluent-bit/etc/parsers.conf
    storage.path                 /fluent-bit/state
    storage.type                 filesystem
    storage.total_limit_size     10G
    storage.max_chunks_up        128
    storage.pause_on_chunks_overlimit On
    storage.backlog.mem_limit    32MB

[INPUT]
    Name              tail
    Path              /logs/cowrie/cowrie/cowrie.json
    Tag               honeypot.cowrie.${VM_ID}
    Parser            cowrie_json
    DB                /fluent-bit/state/cowrie.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[INPUT]
    Name              tail
    Path              /logs/dionaea/dionaea.json
    Tag               honeypot.dionaea.${VM_ID}
    Parser            dionaea_json
    DB                /fluent-bit/state/dionaea.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[INPUT]
    Name              tail
    Path              /logs/conpot/conpot.json
    Tag               honeypot.conpot.${VM_ID}
    Parser            conpot_json
    DB                /fluent-bit/state/conpot.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[INPUT]
    Name              tail
    Path              /logs/elasticpot/elasticpot.json
    Tag               honeypot.elasticpot.${VM_ID}
    Parser            elasticpot_json
    DB                /fluent-bit/state/elasticpot.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[INPUT]
    Name              tail
    Path              /logs/rdpy/rdpy.log
    Tag               honeypot.rdpy.${VM_ID}
    DB                /fluent-bit/state/rdpy.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[INPUT]
    Name              tail
    Path              /logs/honeytrap/honeytrap.log
    Tag               honeypot.honeytrap.${VM_ID}
    Parser            honeytrap_json
    DB                /fluent-bit/state/honeytrap.db
    storage.type      filesystem
    Mem_Buf_Limit     10MB
    Buffer_Chunk_Size 512k
    Buffer_Max_Size   512k
    Refresh_Interval  5
    Read_from_Head    On

[FILTER]
    Name   throttle
    Match  *
    Rate   100
    Window 5

[FILTER]
    Name   record_modifier
    Match  *
    Record vm_id  ${VM_ID}
    Record source honeypot

[FILTER]
    Name   lua
    Match  honeypot.*
    script /fluent-bit/etc/reformat-timestamp.lua
    call   reformat_timestamp

[FILTER]
    Name      modify
    Match     honeypot.cowrie.*
    Rename    eventid   event_type
    Rename    src_ip    src_addr
    Rename    dst_ip    dst_addr
    Rename    session   session_id
    Add       honeypot_type cowrie

[FILTER]
    Name      modify
    Match     honeypot.cowrie.*
    Remove    compCS
    Remove    encCS
    Remove    kexAlgs
    Remove    keyAlgs
    Remove    macCS
    Remove    langCS

[FILTER]
    Name         nest
    Match        honeypot.dionaea.*
    Operation    lift
    Nested_under connection

[FILTER]
    Name         nest
    Match        honeypot.dionaea.*
    Operation    lift
    Nested_under remote
    Add_prefix   remote_

[FILTER]
    Name         nest
    Match        honeypot.dionaea.*
    Operation    lift
    Nested_under local
    Add_prefix   local_

[FILTER]
    Name      modify
    Match     honeypot.dionaea.*
    Rename    remote_address  src_addr
    Rename    remote_port     src_port
    Rename    local_address   dst_addr
    Rename    local_port      dst_port
    Rename    protocol        service
    Rename    transport       transport_proto
    Rename    type            event_type
    Add       honeypot_type   dionaea

[FILTER]
    Name         rewrite_tag
    Match        honeypot.dionaea.*
    Rule         \$event_type ^(accept|reject|connection|listen)\$ honeypot.noise.dionaea.${VM_ID} true

[FILTER]
    Name         throttle
    Match        honeypot.noise.dionaea.*
    Rate         1
    Window       5
    Interval     5s
    Print_Status false

[FILTER]
    Name      modify
    Match     honeypot.dionaea.*
    Remove    remote_hostname

[FILTER]
    Name  modify
    Match honeypot.conpot.*
    Add   honeypot_type conpot

[FILTER]
    Name  modify
    Match honeypot.elasticpot.*
    Add   honeypot_type elasticpot

[FILTER]
    Name  modify
    Match honeypot.rdpy.*
    Add   honeypot_type rdpy

[FILTER]
    Name  modify
    Match honeypot.honeytrap.*
    Add   honeypot_type honeytrap

[OUTPUT]
    Name              nats
    Match             *
    Host              127.0.0.1
    Port              4222
    Retry_Limit       False
FBEOF

# Pre-create cowrie log path so Fluent Bit registers inotify watch on startup
sudo mkdir -p /var/lib/docker/volumes/cowrie-var/_data/log/cowrie
sudo touch /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json

# Idempotent: recreate fluent-bit if config changes
if container_exists "fluent-bit-hp"; then
    warn "Container fluent-bit-hp already exists. Recreating with latest config..."
    sudo docker rm -f fluent-bit-hp
fi

log "Starting Fluent Bit..."
sudo docker run -d \
    --name fluent-bit-hp \
    --restart unless-stopped \
    --network host \
    -v /var/lib/docker/volumes/cowrie-var/_data/log:/logs/cowrie:ro \
    -v /var/lib/docker/volumes/dionaea/_data/var/lib/dionaea:/logs/dionaea:ro \
    -v /var/lib/docker/volumes/conpot-data/_data:/logs/conpot:ro \
    -v /var/lib/docker/volumes/elasticpot/_data:/logs/elasticpot:ro \
    -v /var/lib/docker/volumes/rdpy/_data:/logs/rdpy:ro \
    -v /var/lib/docker/volumes/honeytrap-data/_data:/logs/honeytrap:ro \
    -v "${FB_DIR}/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro" \
    -v "${FB_DIR}/parsers.conf:/fluent-bit/etc/parsers.conf:ro" \
    -v "${FB_DIR}/reformat-timestamp.lua:/fluent-bit/etc/reformat-timestamp.lua:ro" \
    -v "${FB_DIR}/state:/fluent-bit/state" \
    fluent/fluent-bit:4.2 \
    /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluent-bit.conf

log "Fluent Bit started."



# ============================================================
# ZABBIX AGENT
# ============================================================

if ! command -v zabbix_agent2 &>/dev/null; then
    log "Installing Zabbix Agent 2..."
    wget -q https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb \
        -O /tmp/zabbix-release.deb
    sudo dpkg -i /tmp/zabbix-release.deb
    sudo apt-get update -y
    sudo apt-get install -y zabbix-agent2 zabbix-agent2-plugin-*
else
    info "Zabbix Agent 2 already installed, skipping."
fi

ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
sudo sed -i "/^ServerActive=/c\\ServerActive=103.19.110.157" "$ZABBIX_CONF" \
    || echo "ServerActive=103.19.110.157" | sudo tee -a "$ZABBIX_CONF"
sudo sed -i "/^Hostname=/c\\Hostname=${ZABBIX_HOSTNAME}" "$ZABBIX_CONF" \
    || echo "Hostname=${ZABBIX_HOSTNAME}" | sudo tee -a "$ZABBIX_CONF"

sudo systemctl enable zabbix-agent2
sudo systemctl restart zabbix-agent2
log "Zabbix Agent 2 configured: Hostname=${ZABBIX_HOSTNAME}"

# ============================================================
# ADDITIONAL SCRIPTS
# ============================================================

bash <(curl -s https://raw.githubusercontent.com/sguresearcher/IHP-Honeypot/main/dlplog.sh) || \
    warn "dlplog.sh failed to run, continuing..."

# ============================================================
# FINAL STATUS
# ============================================================

sleep 5
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║      HONEYPOT v2.3 — INSTALLATION DONE       ║"
echo "╠══════════════════════════════════════════════╣"
printf  "║  VM_ID  : %-34s║\n" "${VM_ID}"
printf  "║  NATS   : %-34s║\n" "${NATS_HOSTS}:${NATS_PORT}"
printf  "║  TLS    : %-34s║\n" "${NATS_TLS_ENABLED}"
printf  "║  SSH    : %-34s║\n" "port ${NEW_SSH_PORT}"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "=== Running Containers ==="
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo "=== NATS Leaf Connection ==="
sudo docker logs nats-leaf 2>&1 | grep -iE "(leaf|tls|error|connected)" | tail -5 || echo "  (no logs yet)"
echo ""
echo "=== NATS Leaf Config (TLS section) ==="
if [[ "$NATS_TLS_ENABLED" == "true" ]]; then
    echo "  URL scheme : ${NATS_URL_SCHEME}://"
    echo "  CA cert    : ${NATS_DIR}/certs/ca.pem"
    echo "  Skip verify: ${TLS_SKIP_VERIFY}"
else
    echo "  TLS: not active (plain connection)"
fi
echo ""
echo "=== Fluent Bit Status ==="
sudo docker logs fluent-bit-hp 2>&1 | tail -5 || echo "  (no logs yet)"