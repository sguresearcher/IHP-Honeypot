#!/bin/bash
# ============================================================
# HONEYPOT INSTALLER v2.3
# Idempotent — aman dijalankan berulang kali
# Fix: URL-encode password NATS, dionaea volume, hapus -it flag
# Fix: cleanup container lama by port (nama random Docker)
# + TLS support untuk koneksi ke NATS Hub (CA cert)
# + Malware Uploader (dionaea binaries → NATS JetStream Object Store)
# + Single-phase install — tidak perlu reboot
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
step()   { echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  $*"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

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

# Bebaskan port: hentikan Docker container DAN proses host yang bind port tsb
free_port() {
    local port="$1"

    # Lewati port 22888 (SSH aktif)
    if [[ "$port" == "22888" ]]; then
        warn "Skipping protected port $port"
        return
    fi

    # 1) Docker container yang publish port ini
    local ids
    ids=$(sudo docker ps -q --filter "publish=${port}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        warn "  Docker: port ${port} dipakai container — menghentikan..."
        echo "$ids" | xargs sudo docker rm -f 2>/dev/null || true
    fi

    # 2) Proses host yang masih menggunakan port ini
    if sudo ss -tlnup 2>/dev/null | grep -q ":${port}[[:space:]]"; then
        warn "  Host: port ${port} dipakai proses host — mematikan..."
        sudo fuser -k "${port}/tcp" 2>/dev/null || true
        sudo fuser -k "${port}/udp" 2>/dev/null || true
    fi
}

free_ports() {
    log "Membebaskan ports: $*"
    for p in "$@"; do
        free_port "$p"
    done
    sleep 1   # beri kernel waktu release socket
}

# ============================================================
# PREFLIGHT CHECKS
# ============================================================

step "[STEP 1/12] PREFLIGHT CHECK"
read -p "Do you accept the terms and conditions? (y/n) " -r
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    die "Jangan jalankan sebagai root. Gunakan user biasa dengan sudo."
fi

sudo -l &>/dev/null || die "User harus punya sudo permissions."

# ============================================================
# INPUT KONFIGURASI
# ============================================================
step "[STEP 2/12] INPUT KONFIGURASI"

ENV_CACHE="/var/honeypot_env.cache"
USE_CACHE=false

if [ -f "$ENV_CACHE" ]; then
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║   Previous Configuration Found       ║"
    echo "╚══════════════════════════════════════╝"
    read -p "Gunakan konfigurasi sebelumnya? [Y/n, default: Y]: " REUSE_ENV
    REUSE_ENV=${REUSE_ENV:-"Y"}
    if [[ "$REUSE_ENV" =~ ^[Yy]$ ]]; then
        if [ -r "$ENV_CACHE" ]; then
            source "$ENV_CACHE"
        else
            warn "Tidak bisa membaca $ENV_CACHE — masalah permission"
        fi
        USE_CACHE=true
        LEAF_CREDS_CONTENT=$(echo "$LEAF_CREDS_B64" | base64 -d)
        if [ "$NATS_TLS_ENABLED" = "true" ]; then
            TLS_CA_CONTENT=$(echo "$TLS_CA_B64" | base64 -d)
        fi
        log "Konfigurasi sebelumnya berhasil dimuat dari $ENV_CACHE."
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
echo "    Silakan COPY seluruh isi text credentials (.creds) milik Tenant ini."
echo "    Lalu PASTE di terminal ini. Setelah semua ter-paste, ketik 'EOF' pada baris baru dan tekan Enter:"
echo "    --------------------------------------------------------"

while IFS= read -r line; do
  if [[ "$line" == "EOF" ]]; then
    break
  fi
  LEAF_CREDS_CONTENT+="$line"$'\n'
done

if [[ -z "$(echo -n "$LEAF_CREDS_CONTENT" | tr -d '[:space:]')" ]]; then
  die "Kredensial tidak boleh kosong!"
fi
echo "    --------------------------------------------------------"
log "Kredensial berhasil dibaca."

# ============================================================
# INPUT TLS CONFIGURATION
# ============================================================

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      TLS Configuration               ║"
echo "╚══════════════════════════════════════╝"
echo "    TLS mengenkripsi koneksi antara leaf node dan NATS Hub."
echo "    Kamu butuh CA certificate dari NATS Hub server."
echo ""
read -p "Aktifkan TLS ke NATS Hub? [Y/n, default: Y]: " USE_TLS
USE_TLS=${USE_TLS:-"Y"}

NATS_TLS_ENABLED=false
TLS_CA_CONTENT=""
TLS_SKIP_VERIFY=false
NATS_URL_SCHEME="nats"

if [[ "$USE_TLS" =~ ^[Yy]$ ]]; then
    NATS_TLS_ENABLED=true
    NATS_URL_SCHEME="tls"

    echo ""
    echo "[?] Sumber CA Certificate"
    echo "    [1] Paste isi CA cert langsung (inline)"
    echo "    [2] Masukkan path file CA cert yang sudah ada"
    read -p "    Pilih [1/2, default: 1]: " TLS_CERT_CHOICE
    TLS_CERT_CHOICE=${TLS_CERT_CHOICE:-"1"}

    if [[ "$TLS_CERT_CHOICE" == "2" ]]; then
        read -p "    Path file CA cert (.pem): " CA_CERT_PATH
        [[ -f "$CA_CERT_PATH" ]] || die "File CA cert tidak ditemukan: ${CA_CERT_PATH}"
        TLS_CA_CONTENT=$(cat "$CA_CERT_PATH")
        log "CA cert dibaca dari: ${CA_CERT_PATH}"
    else
        echo ""
        echo "    Silakan PASTE isi CA certificate (.pem) di bawah ini."
        echo "    Setelah selesai, ketik 'EOF' pada baris baru dan tekan Enter:"
        echo "    --------------------------------------------------------"
        while IFS= read -r line; do
            if [[ "$line" == "EOF" ]]; then
                break
            fi
            TLS_CA_CONTENT+="$line"$'\n'
        done
        echo "    --------------------------------------------------------"

        if [[ -z "$(echo -n "$TLS_CA_CONTENT" | tr -d '[:space:]')" ]]; then
            die "CA certificate tidak boleh kosong!"
        fi
        log "CA cert berhasil dibaca (inline)."
    fi

    echo ""
    read -p "    Skip TLS verification (tidak direkomendasikan, hanya untuk dev)? [y/N, default: N]: " TLS_SKIP_INPUT
    TLS_SKIP_INPUT=${TLS_SKIP_INPUT:-"N"}
    if [[ "$TLS_SKIP_INPUT" =~ ^[Yy]$ ]]; then
        TLS_SKIP_VERIFY=true
        warn "TLS verify dinonaktifkan (insecure_skip_verify). Hanya untuk testing!"
    fi

    log "TLS diaktifkan (URL scheme: ${NATS_URL_SCHEME}://)."
else
    log "TLS dinonaktifkan. Koneksi plain tanpa enkripsi."
fi



# ============================================================
# ZABBIX CONFIGURATION
# ============================================================

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      Zabbix Configuration            ║"
echo "╚══════════════════════════════════════╝"
read -p "Zabbix Hostname (nama VM ini): " ZABBIX_HOSTNAME
[[ -n "$ZABBIX_HOSTNAME" ]] || die "Zabbix hostname tidak boleh kosong."

    # Simpan ke cache
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
    log "Konfigurasi baru disimpan ke $ENV_CACHE."

fi # end USE_CACHE = false

step "[STEP 3/12] AUTO VM ID"

# ============================================================
# AUTO VM ID
# ============================================================

HOSTNAME_ID=$(hostname | tr '[:upper:]' '[:lower:]')
IP_SUFFIX=$(curl -s --max-time 5 ifconfig.me 2>/dev/null | awk -F. '{print $4}')
IP_SUFFIX=${IP_SUFFIX:-"unknown"}
VM_ID="${HOSTNAME_ID}-${IP_SUFFIX}"
log "VM_ID: ${VM_ID}"

# ============================================================
# PERSIAPAN SISTEM
# ============================================================

step "[STEP 4/12] PERSIAPAN SISTEM — APT UPDATE & UPGRADE"
log "Mempersiapkan sistem..."

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

log "Menjalankan apt-get update..."
sudo apt-get update -y
log "Menjalankan apt-get upgrade (non-interactive, needrestart disupres)..."
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 \
    apt-get upgrade -y \
    -o Dpkg::Options::="--force-confnew"
sudo apt-get install -y psmisc iproute2 &>/dev/null || true

# --- Limits ---
LIMITS_CONF="/etc/security/limits.conf"
for line in \
    "root soft nofile 65536" \
    "root hard nofile 65536" \
    "* soft nofile 65536" \
    "* hard nofile 65536"; do
    grep -qF "$line" "$LIMITS_CONF" || echo "$line" | sudo tee -a "$LIMITS_CONF" >/dev/null
done
# Terapkan ke sesi ini langsung tanpa reboot
ulimit -n 65536 2>/dev/null || true

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
    log "Swap 1G aktif."
else
    info "Swap sudah ada, skip."
fi

# ============================================================
# DOCKER
# ============================================================
step "[STEP 5/12] INSTALASI DOCKER"

if ! command -v docker &>/dev/null; then
    log "Menginstall Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo groupadd docker 2>/dev/null || true
    sudo usermod -aG docker "$USER"
    sudo systemctl enable docker.service containerd.service
    log "Docker terinstall."
else
    info "Docker sudah ada ($(docker --version)), skip install."
fi

# Pastikan user bisa akses docker tanpa sudo di sesi ini
if ! groups | grep -q docker; then
    warn "User belum di group docker. Gunakan sudo atau re-login."
fi

# ============================================================
# INSECURE REGISTRY
# ============================================================

REGISTRY_IP="103.19.110.148:5000"
DAEMON_JSON="/etc/docker/daemon.json"

if ! grep -q "$REGISTRY_IP" "$DAEMON_JSON" 2>/dev/null; then
    log "Menambahkan insecure registry..."
    echo "{ \"insecure-registries\":[\"${REGISTRY_IP}\"] }" | sudo tee "$DAEMON_JSON"
    sudo systemctl restart docker
else
    info "Insecure registry sudah dikonfigurasi, skip."
fi

# ============================================================
# SSH PORT CHANGE
# ============================================================
step "[STEP 6/12] PERUBAHAN PORT SSH"

NEW_SSH_PORT="22888"
CURRENT_SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")

if [ "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]; then
    warn "SSH port akan diubah ke ${NEW_SSH_PORT}. Pastikan port tersebut sudah dibuka di firewall!"
    read -p "Lanjut? (y/n) " -r
    [[ $REPLY =~ ^[Yy]$ ]] || die "Dibatalkan user."
    sudo sed -i -e "s/^#\?Port .*/Port ${NEW_SSH_PORT}/" /etc/ssh/sshd_config
    if command -v ufw &>/dev/null; then
        sudo ufw allow "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
        log "Port ${NEW_SSH_PORT}/tcp diizinkan di UFW."
    fi
else
    info "sshd_config sudah Port ${NEW_SSH_PORT}."
fi

# Hentikan ssh.socket SEBELUM restart sshd.
# Di Ubuntu 22.04+, ssh.socket (systemd socket activation) memegang port 22
# secara terpisah dari sshd.service. Harus dihentikan agar:
#   1. sshd bisa mengikat port 22888 tanpa konflik
#   2. port 22 bebas untuk container cowrie honeypot
if systemctl list-unit-files 2>/dev/null | grep -q "^ssh\.socket"; then
    sudo systemctl stop ssh.socket 2>/dev/null || true
    sudo systemctl disable ssh.socket 2>/dev/null || true
    info "ssh.socket dihentikan dan dinonaktifkan."
fi

# (Re)start sshd untuk menerapkan konfigurasi port
if systemctl list-unit-files 2>/dev/null | grep -q "^sshd\.service"; then
    sudo systemctl restart sshd
else
    sudo systemctl restart ssh
fi
sleep 2

if sudo ss -tlnp | grep -q ":${NEW_SSH_PORT}[[:space:]]"; then
    log "SSH aktif di port ${NEW_SSH_PORT}."
else
    warn "SSH tidak terdeteksi di port ${NEW_SSH_PORT} — verifikasi koneksi sebelum melanjutkan."
fi

# ============================================================
# PULL IMAGES
# ============================================================
step "[STEP 7/12] PULL HONEYPOT DOCKER IMAGES"

IMAGES=(
    "cowrie" "conpot" "rdpy" "elasticpot" "dionaea" "honeytrap"
)

log "Pulling honeypot images..."
for img in "${IMAGES[@]}"; do
    if sudo docker image inspect "${REGISTRY_IP}/${img}:latest" &>/dev/null; then
        info "Image ${img} sudah ada, skip pull."
    else
        log "Pulling ${img}..."
        sudo docker pull "${REGISTRY_IP}/${img}:latest"
    fi
done

# ============================================================
# VOLUMES
# ============================================================
step "[STEP 8/12] MEMBUAT DOCKER VOLUMES"

VOLUMES=("cowrie-var" "cowrie-etc" "gridpot" "elasticpot" "dionaea" "honeytrap-data" "conpot-data")

log "Membuat Docker volumes..."
for vol in "${VOLUMES[@]}"; do
    if sudo docker volume inspect "$vol" &>/dev/null; then
        info "Volume ${vol} sudah ada, skip."
    else
        sudo docker volume create "$vol"
        log "Volume ${vol} dibuat."
    fi
done

sudo mkdir -p /var/lib/docker/volumes/rdpy/_data

# ============================================================
# HONEYPOT CONTAINERS
# Idempotent: skip jika container sudah running, recreate jika exited
# ============================================================
step "[STEP 9/12] MENJALANKAN HONEYPOT CONTAINERS"

start_container() {
    local name="$1"
    shift
    if container_running "$name"; then
        info "Container ${name} sudah running, skip."
        return 0
    fi
    if container_exists "$name"; then
        warn "Container ${name} ada tapi tidak running. Menghapus dan recreate..."
        sudo docker rm -f "$name"
    fi
    log "Menjalankan container ${name}..."
    sudo docker run --name "$name" "$@"
}

# Nama container hardcoded agar idempotent dan mudah diidentifikasi
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
step "[STEP 10/12] SETUP NATS LEAF NODE"

NATS_DIR="/opt/nats-leaf"
sudo mkdir -p "${NATS_DIR}"
sudo mkdir -p "${NATS_DIR}/certs"
sudo mkdir -p "${NATS_DIR}/creds"

echo "$LEAF_CREDS_CONTENT" | sudo tee "${NATS_DIR}/creds/leafnode.creds" >/dev/null
sudo chmod 600 "${NATS_DIR}/creds/leafnode.creds"
log "Credentials disimpan ke: ${NATS_DIR}/creds/leafnode.creds"

# ============================================================
# SIMPAN CA CERT (jika TLS aktif)
# ============================================================

TLS_BLOCK=""
NATS_CERTS_VOLUME_ARG=""

if [[ "$NATS_TLS_ENABLED" == "true" ]]; then
    echo "$TLS_CA_CONTENT" | sudo tee "${NATS_DIR}/certs/ca.pem" >/dev/null
    sudo chmod 644 "${NATS_DIR}/certs/ca.pem"
    log "CA cert disimpan ke: ${NATS_DIR}/certs/ca.pem"

    # Blok TLS untuk NATS leaf config
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

# Build leaf remotes dari comma-separated IPs
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

# Tulis config (selalu re-generate agar password terbaru selalu dipakai)
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

log "NATS leaf config ditulis ke: ${NATS_DIR}/nats-leaf.conf"
if [[ "$NATS_TLS_ENABLED" == "true" ]]; then
    log "NATS URL scheme: ${NATS_URL_SCHEME}:// (terenkripsi TLS)"
    log "CA cert di-mount ke container di: /certs/ca.pem"
fi

# Idempotent: hapus container lama jika config berubah / tidak running
if container_exists "nats-leaf"; then
    warn "Container nats-leaf sudah ada. Recreating dengan config terbaru..."
    sudo docker rm -f nats-leaf
fi

log "Menjalankan NATS Leaf Node..."
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

log "NATS Leaf Node started. Menunggu koneksi ke hub..."
sleep 5
NATS_LEAF_STATUS=$(sudo docker logs nats-leaf 2>&1 | tail -5)
echo "$NATS_LEAF_STATUS"

# ============================================================
# FLUENT BIT
# ============================================================
step "[STEP 11/12] SETUP FLUENT BIT"

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

# Pre-create path log cowrie agar Fluent Bit langsung daftarkan inotify watch saat startup
sudo mkdir -p /var/lib/docker/volumes/cowrie-var/_data/log/cowrie
sudo touch /var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json

# Idempotent: recreate fluent-bit jika config berubah
if container_exists "fluent-bit-hp"; then
    warn "Container fluent-bit-hp sudah ada. Recreating dengan config terbaru..."
    sudo docker rm -f fluent-bit-hp
fi

log "Menjalankan Fluent Bit..."
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
step "[STEP 12/12] INSTALASI ZABBIX AGENT"

if ! command -v zabbix_agent2 &>/dev/null; then
    log "Menginstall Zabbix Agent 2..."
    wget -q https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb \
        -O /tmp/zabbix-release.deb
    sudo dpkg -i /tmp/zabbix-release.deb
    sudo apt-get update -y
    sudo apt-get install -y zabbix-agent2 zabbix-agent2-plugin-*
else
    info "Zabbix Agent 2 sudah ada, skip install."
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
    warn "dlplog.sh gagal dijalankan, lanjut..."

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
    echo "  TLS: tidak aktif (plain connection)"
fi
echo ""
echo "=== Fluent Bit Status ==="
sudo docker logs fluent-bit-hp 2>&1 | tail -5 || echo "  (no logs yet)"
