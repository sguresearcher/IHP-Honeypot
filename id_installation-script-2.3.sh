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

    # Cek apakah port yang akan dibebaskan adalah port SSH aktif saat ini
    local active_ssh_port=""
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        active_ssh_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
    fi

    # 1) Docker container yang publish port ini
    local ids
    ids=$(sudo docker ps -q --filter "publish=${port}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        warn "  Docker: port ${port} dipakai container — menghentikan..."
        echo "$ids" | xargs sudo docker rm -f 2>/dev/null || true
    fi

    # 2) Proses host yang masih menggunakan port ini
    # Jika port yang dibebaskan adalah port SSH aktif Anda saat ini, matikan HANYA proses induk listener (bukan koneksi aktif) agar sesi SSH tidak terputus
    if [[ -n "$active_ssh_port" && "$port" == "$active_ssh_port" ]]; then
        warn "  Host: Port $port adalah port SSH aktif Anda saat ini. Mematikan HANYA proses induk listener agar koneksi Anda tidak terputus..."
        local listener_pids
        listener_pids=$(sudo ss -tlnp 2>/dev/null | grep ":${port}[[:space:]]" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u || true)
        if [[ -n "$listener_pids" ]]; then
            log "  Mematikan PID listener: $listener_pids pada port $port..."
            echo "$listener_pids" | xargs sudo kill -9 2>/dev/null || true
        fi
    else
        if sudo ss -tlnup 2>/dev/null | grep -q ":${port}[[:space:]]"; then
            warn "  Host: port ${port} dipakai proses host — mematikan..."
            sudo fuser -k "${port}/tcp" 2>/dev/null || true
            sudo fuser -k "${port}/udp" 2>/dev/null || true
        fi
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

step "[STEP 1/13] PREFLIGHT CHECK"
read -p "Do you accept the terms and conditions? (y/n) " -r
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    die "Jangan jalankan sebagai root. Gunakan user biasa dengan sudo."
fi

sudo -l &>/dev/null || die "User harus punya sudo permissions."

# ============================================================
# INPUT KONFIGURASI
# ============================================================
step "[STEP 2/13] INPUT KONFIGURASI"

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
read -p "NATS Hub IPs (comma-separated) [default: 103.19.110.151]: " NATS_HOSTS
NATS_HOSTS=${NATS_HOSTS:-"103.19.110.151"}
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

step "[STEP 3/13] AUTO VM ID"

# ============================================================
# AUTO VM ID
# ============================================================

HOSTNAME_ID=$(hostname | tr '[:upper:]' '[:lower:]')

# Menggunakan timeout (GNU coreutils) jika tersedia untuk mencegah dns lookup hang indefinitely
IP_PUBLIC=""
if command -v timeout &>/dev/null; then
    IP_PUBLIC=$(timeout 5 curl -s --max-time 5 ifconfig.me 2>/dev/null || true)
else
    IP_PUBLIC=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || true)
fi

IP_SUFFIX=""
if [[ -n "$IP_PUBLIC" && "$IP_PUBLIC" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IP_SUFFIX=$(echo "$IP_PUBLIC" | awk -F. '{print $4}')
fi

# Fallback ke IP lokal jika gagal mendapatkan IP publik
if [[ -z "$IP_SUFFIX" ]]; then
    info "Gagal mendapatkan IP publik, mencoba menggunakan IP lokal..."
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    if [[ -n "$LOCAL_IP" && "$LOCAL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        IP_SUFFIX=$(echo "$LOCAL_IP" | awk -F. '{print $4}')
    fi
fi

IP_SUFFIX=${IP_SUFFIX:-"unknown"}
VM_ID="${HOSTNAME_ID}-${IP_SUFFIX}"
log "VM_ID: ${VM_ID}"

# ============================================================
# PERSIAPAN SISTEM
# ============================================================

step "[STEP 4/13] PERSIAPAN SISTEM — APT UPDATE & UPGRADE"
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
sudo apt-get install -y psmisc iproute2 curl &>/dev/null || true

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
step "[STEP 5/13] INSTALASI DOCKER"

if ! command -v docker &>/dev/null; then
    log "Menginstall Docker..."
    if command -v curl &>/dev/null; then
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    elif command -v wget &>/dev/null; then
        wget -qO /tmp/get-docker.sh https://get.docker.com
    else
        warn "curl dan wget tidak ditemukan. Mencoba menginstall curl..."
        sudo apt-get update -y && sudo apt-get install -y curl
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    fi
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
step "[STEP 6/13] PERUBAHAN PORT SSH"

NEW_SSH_PORT="22888"

# 1. Terapkan konfigurasi port baru ke sshd_config (tradisional/service)
# Beri tanda komentar pada semua directive Port yang aktif di config utama untuk menghindari konflik port
sudo sed -i -E 's/^[[:space:]]*Port[[:space:]]/#&/g' /etc/ssh/sshd_config

if [ -d /etc/ssh/sshd_config.d ]; then
    log "Menulis konfigurasi port ke /etc/ssh/sshd_config.d/00-honeypot.conf..."
    echo "Port ${NEW_SSH_PORT}" | sudo tee /etc/ssh/sshd_config.d/00-honeypot.conf >/dev/null
    # Beri tanda komentar pada semua directive Port di file-file lain di dalam sshd_config.d agar tidak bind ke port 22
    find /etc/ssh/sshd_config.d/ -type f ! -name "00-honeypot.conf" -exec sudo sed -i -E 's/^[[:space:]]*Port[[:space:]]/#&/g' {} + 2>/dev/null || true
else
    log "Mengubah port di /etc/ssh/sshd_config..."
    # Hapus semua baris Port yang aktif agar tidak konflik
    sudo sed -i -E '/^[[:space:]]*Port[[:space:]]/d' /etc/ssh/sshd_config
    # Tambahkan Port 22888 di baris baru
    echo "Port ${NEW_SSH_PORT}" | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi

# Izinkan port di firewall UFW
if command -v ufw &>/dev/null; then
    sudo ufw allow "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    log "Port ${NEW_SSH_PORT}/tcp diizinkan di UFW."
fi

# 2. Kembalikan dari systemd socket activation ke service SSH tradisional agar selalu aktif saat boot
# Jika ssh.socket ada, kita juga override konfigurasinya agar menggunakan port baru.
# Ini mencegahnya mengikat port 22 meskipun unit socket activation tidak sepenuhnya dinonaktifkan.
if systemctl list-unit-files 2>/dev/null | grep -q "^ssh\.socket"; then
    log "Mengonfigurasi override systemd ssh.socket ke port ${NEW_SSH_PORT}..."
    sudo mkdir -p /etc/systemd/system/ssh.socket.d
    cat <<EOF | sudo tee /etc/systemd/system/ssh.socket.d/addresses.conf >/dev/null
[Socket]
ListenStream=
ListenStream=${NEW_SSH_PORT}
EOF
    log "Menonaktifkan systemd ssh.socket..."
    sudo systemctl stop ssh.socket 2>/dev/null || true
    sudo systemctl disable ssh.socket 2>/dev/null || true
fi

# Jalankan daemon-reload untuk menerapkan override socket dan perubahan konfigurasi
sudo systemctl daemon-reload

# Aktifkan dan restart service ssh/sshd tradisional
if systemctl list-unit-files 2>/dev/null | grep -q "^sshd\.service"; then
    sudo systemctl enable sshd 2>/dev/null || true
    sudo systemctl restart sshd
else
    sudo systemctl enable ssh 2>/dev/null || true
    sudo systemctl restart ssh
fi
sleep 2

# Verifikasi keaktifan port baru
if sudo ss -tlnp | grep -q ":${NEW_SSH_PORT}[[:space:]]"; then
    log "SSH aktif di port ${NEW_SSH_PORT}."
else
    warn "SSH tidak terdeteksi di port ${NEW_SSH_PORT} — verifikasi koneksi sebelum melanjutkan."
fi

# ============================================================
# PULL IMAGES
# ============================================================
step "[STEP 7/13] PULL HONEYPOT DOCKER IMAGES"

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
step "[STEP 8/13] MEMBUAT DOCKER VOLUMES"

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
step "[STEP 9/13] MENJALANKAN HONEYPOT CONTAINERS"

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
step "[STEP 10/13] SETUP NATS LEAF NODE"

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
step "[STEP 11/13] SETUP FLUENT BIT"

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
step "[STEP 12/13] INSTALASI ZABBIX AGENT"

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
sudo sed -i "/^ServerActive=/c\\ServerActive=103.19.110.151" "$ZABBIX_CONF" \
    || echo "ServerActive=103.19.110.151" | sudo tee -a "$ZABBIX_CONF"
sudo sed -i "/^Hostname=/c\\Hostname=${ZABBIX_HOSTNAME}" "$ZABBIX_CONF" \
    || echo "Hostname=${ZABBIX_HOSTNAME}" | sudo tee -a "$ZABBIX_CONF"

sudo systemctl enable zabbix-agent2
sudo systemctl restart zabbix-agent2
log "Zabbix Agent 2 configured: Hostname=${ZABBIX_HOSTNAME}"

# ============================================================
# HONEYPOT INACTIVITY WATCHDOG
# ============================================================
step "[STEP 13/13] SETUP HONEYPOT WATCHDOG"

WATCHDOG_DIR="/opt/honeypot-watchdog"
WATCHDOG_SCRIPT="${WATCHDOG_DIR}/honeypot-watchdog.sh"
sudo mkdir -p "${WATCHDOG_DIR}"

log "Menulis script Honeypot Watchdog..."
sudo tee "${WATCHDOG_SCRIPT}" > /dev/null << 'WATCHDOG_EOF'
#!/usr/bin/env bash
# ============================================================
# Honeypot Inactivity Watchdog v1.0
# Monitors honeypot containers and restarts any container
# that has not produced/sent log data within 3 hours.
#
# Safe against restart loops via container uptime grace period.
# Supported containers: cowrie-hp, dionaea-hp, rdpy-hp,
#                       elasticpot-hp, honeytrap-hp, conpot-hp
# Auxiliary checks:     fluent-bit-hp, nats-leaf
# ============================================================

set -euo pipefail

DEFAULT_TIMEOUT=10800 # 3 hours in seconds
TIMEOUT_SECS="${WATCHDOG_TIMEOUT:-$DEFAULT_TIMEOUT}"
LOG_FILE="/var/log/honeypot-watchdog.log"
LOCK_FILE="/var/lock/honeypot-watchdog.lock"
MAX_LOG_SIZE=5242880 # 5 MB

DRY_RUN=false
STATUS_ONLY=false
VERBOSE=false

HONEYPOTS=(
    "cowrie-hp:Cowrie:cowrie-var:log/cowrie/cowrie.json"
    "dionaea-hp:Dionaea:dionaea:var/lib/dionaea/dionaea.json"
    "rdpy-hp:RDPy:rdpy:rdpy.log"
    "elasticpot-hp:Elasticpot:elasticpot:elasticpot.json"
    "honeytrap-hp:Honeytrap:honeytrap-data:honeytrap.log"
    "conpot-hp:Conpot:conpot-data:conpot.json"
)

AUX_CONTAINERS=("fluent-bit-hp" "nats-leaf")

log_msg() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local line="[$timestamp] $*"
    if [ "$STATUS_ONLY" = false ] || [ "$VERBOSE" = true ]; then
        echo "$line"
    fi
    if [ -w "$(dirname "$LOG_FILE" 2>/dev/null || echo /tmp)" ]; then
        echo "$line" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        local size
        size=$(stat -c %s "$LOG_FILE" 2>/dev/null || stat -f %z "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            tail -n 5000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null || true
            log_msg "[INFO] Rotated log file $LOG_FILE (kept last 5000 lines)"
        fi
    fi
}

docker_cmd() {
    if ! command -v docker &>/dev/null; then
        echo "Error: docker command not found" >&2
        return 1
    fi

    if docker info &>/dev/null; then
        docker "$@"
    elif [ "$(id -u)" -eq 0 ]; then
        docker "$@"
    elif sudo -n true 2>/dev/null; then
        sudo docker "$@"
    else
        if [ -t 0 ]; then
            sudo docker "$@"
        else
            echo "Error: root or sudo permissions required to query Docker." >&2
            return 1
        fi
    fi
}

iso_to_epoch() {
    local iso="$1"
    [ -z "$iso" ] && echo "0" && return

    local epoch
    epoch=$(date -d "$iso" +%s 2>/dev/null || true)
    if [ -n "$epoch" ]; then
        echo "$epoch"
        return
    fi

    if command -v python3 &>/dev/null; then
        epoch=$(python3 -c "import datetime, sys; s = sys.argv[1][:19]; print(int(datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()))" "$iso" 2>/dev/null || true)
        if [ -n "$epoch" ]; then
            echo "$epoch"
            return
        fi
    fi

    local clean="${iso%%.*}"
    epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$clean" +%s 2>/dev/null || true)
    if [ -n "$epoch" ]; then
        echo "$epoch"
        return
    fi

    echo "0"
}

get_file_mtime() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "0"
        return
    fi
    local mtime
    mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || echo "0")
    echo "$mtime"
}

format_duration() {
    local total_seconds="$1"
    if [ "$total_seconds" -lt 0 ]; then
        total_seconds=0
    fi
    local hours=$(( total_seconds / 3600 ))
    local mins=$(( (total_seconds % 3600) / 60 ))
    local secs=$(( total_seconds % 60 ))
    if [ "$hours" -gt 0 ]; then
        printf "%dh %02dm" "$hours" "$mins"
    elif [ "$mins" -gt 0 ]; then
        printf "%dm %02ds" "$mins" "$secs"
    else
        printf "%ds" "$secs"
    fi
}

get_log_path() {
    local volume="$1"
    local rel_path="$2"

    local mountpoint=""
    mountpoint=$(docker_cmd volume inspect "$volume" --format '{{.Mountpoint}}' 2>/dev/null || true)

    if [ -z "$mountpoint" ]; then
        mountpoint="/var/lib/docker/volumes/${volume}/_data"
    fi

    echo "${mountpoint}/${rel_path}"
}

print_help() {
    cat <<EOF
Honeypot Inactivity Watchdog v1.0
Usage: \$(basename "\$0") [OPTIONS]

Monitors honeypot Docker containers and automatically restarts any container
that has been inactive (no new logs written) for longer than the timeout period (default: 3 hours).

Options:
  --status, status          Show current status table of all honeypots and exit.
  --dry-run, check          Simulate watchdog check without restarting containers.
  --timeout <seconds>       Set inactivity threshold in seconds (default: 10800 = 3h).
  --install                 Install systemd service and timer (runs every 10 min).
  --uninstall               Disable and remove systemd service and timer.
  -v, --verbose             Enable verbose output.
  -h, --help                Show this help message.

Log file: \$LOG_FILE
Systemd timer: honeypot-watchdog.timer
EOF
}

install_systemd() {
    echo "Installing Honeypot Watchdog systemd service and timer..."

    local script_dest="/usr/local/bin/honeypot-watchdog.sh"
    local symlink_dest="/usr/local/bin/honeypot-watchdog"

    if [ "\$(id -u)" -ne 0 ]; then
        echo "Error: Installation requires root/sudo privileges." >&2
        exit 1
    fi

    cp -f "\$0" "\$script_dest"
    chmod 755 "\$script_dest"
    ln -sf "\$script_dest" "\$symlink_dest"

    cat <<EOF > /etc/systemd/system/honeypot-watchdog.service
[Unit]
Description=Honeypot Inactivity Watchdog (3-hour inactivity restart)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=\$script_dest
StandardOutput=journal
StandardError=journal
EOF

    cat <<EOF > /etc/systemd/system/honeypot-watchdog.timer
[Unit]
Description=Periodic check for honeypot inactivity
Requires=honeypot-watchdog.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable honeypot-watchdog.timer
    systemctl restart honeypot-watchdog.timer

    echo "Watchdog successfully installed and activated!"
    echo "Timer status:"
    systemctl status honeypot-watchdog.timer --no-pager || true
    echo ""
    echo "You can check honeypot status anytime with: sudo honeypot-watchdog --status"
}

uninstall_systemd() {
    echo "Uninstalling Honeypot Watchdog..."
    if [ "\$(id -u)" -ne 0 ]; then
        echo "Error: Uninstallation requires root/sudo privileges." >&2
        exit 1
    fi

    systemctl stop honeypot-watchdog.timer 2>/dev/null || true
    systemctl disable honeypot-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/honeypot-watchdog.service
    rm -f /etc/systemd/system/honeypot-watchdog.timer
    systemctl daemon-reload

    rm -f /usr/local/bin/honeypot-watchdog.sh
    rm -f /usr/local/bin/honeypot-watchdog

    echo "Honeypot Watchdog uninstalled successfully."
}

run_watchdog() {
    local now
    now=\$(date +%s)

    rotate_log

    local restart_count=0
    local healthy_count=0
    local grace_count=0
    local stopped_count=0
    local missing_count=0

    if [ "\$STATUS_ONLY" = true ]; then
        echo "====================================================================================================="
        printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "CONTAINER" "STATUS" "UPTIME" "LAST DATA (MTIME)" "INACTIVE FOR" "ACTION / STATE"
        echo "====================================================================================================="
    fi

    for entry in "\${HONEYPOTS[@]}"; do
        IFS=":" read -r container_name display_name volume rel_path <<< "\$entry"
        local log_path
        log_path=\$(get_log_path "\$volume" "\$rel_path")

        local exists
        exists=\$(docker_cmd ps -a --filter "name=^/\${container_name}\$" --format '{{.Names}}' 2>/dev/null || true)
        if [ -z "\$exists" ]; then
            if [ "\$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$container_name" "MISSING" "-" "N/A" "-" "CONTAINER NOT FOUND"
            else
                log_msg "[WARN] Container \$container_name not found on host."
            fi
            missing_count=\$(( missing_count + 1 ))
            continue
        fi

        local c_status
        c_status=\$(docker_cmd inspect --format '{{.State.Status}}' "\$container_name" 2>/dev/null || echo "unknown")

        if [ "\$c_status" != "running" ]; then
            stopped_count=\$(( stopped_count + 1 ))
            if [ "\$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$container_name" "\$c_status" "-" "N/A" "-" "NEEDS START (EXITED)"
            else
                log_msg "[ALERT] Container \$container_name is not running (status: \$c_status). Starting container..."
                if [ "\$DRY_RUN" = false ]; then
                    docker_cmd start "\$container_name" || docker_cmd restart "\$container_name"
                    log_msg "[OK] Container \$container_name started."
                else
                    log_msg "[DRY-RUN] Would start container \$container_name"
                fi
                restart_count=\$(( restart_count + 1 ))
            fi
            continue
        fi

        local started_at
        started_at=\$(docker_cmd inspect --format '{{.State.StartedAt}}' "\$container_name" 2>/dev/null || echo "")
        local start_epoch
        start_epoch=\$(iso_to_epoch "\$started_at")
        local uptime=0
        if [ "\$start_epoch" -gt 0 ]; then
            uptime=\$(( now - start_epoch ))
            [ "\$uptime" -lt 0 ] && uptime=0
        fi

        local file_mtime
        file_mtime=\$(get_file_mtime "\$log_path")
        local mtime_str="No data yet"
        local inactive_secs=-1

        if [ "\$file_mtime" -gt 0 ]; then
            mtime_str=\$(date -d "@\$file_mtime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -r "\$file_mtime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "\$file_mtime")
            inactive_secs=\$(( now - file_mtime ))
            [ "\$inactive_secs" -lt 0 ] && inactive_secs=0
        fi

        if [ "\$uptime" -lt "\$TIMEOUT_SECS" ]; then
            grace_count=\$(( grace_count + 1 ))
            local inactive_fmt="-"
            [ "\$inactive_secs" -ge 0 ] && inactive_fmt=\$(format_duration "\$inactive_secs")
            if [ "\$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$container_name" "running" "\$(format_duration "\$uptime")" "\$mtime_str" "\$inactive_fmt" "GRACE PERIOD (<$(format_duration "\$TIMEOUT_SECS"))"
            elif [ "\$VERBOSE" = true ]; then
                log_msg "[INFO] Container \$container_name in grace period (uptime \$(format_duration "\$uptime") < \$(format_duration "\$TIMEOUT_SECS"))"
            fi
            continue
        fi

        local needs_restart=false
        local reason=""

        if [ "\$file_mtime" -eq 0 ]; then
            needs_restart=true
            reason="Log file missing or empty after running \$(format_duration "\$uptime")"
        elif [ "\$inactive_secs" -ge "\$TIMEOUT_SECS" ]; then
            needs_restart=true
            reason="No new data written for \$(format_duration "\$inactive_secs") (threshold: \$(format_duration "\$TIMEOUT_SECS"))"
        fi

        if [ "\$needs_restart" = true ]; then
            restart_count=\$(( restart_count + 1 ))
            if [ "\$STATUS_ONLY" = true ]; then
                local inactive_fmt="never"
                [ "\$inactive_secs" -ge 0 ] && inactive_fmt=\$(format_duration "\$inactive_secs")
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$container_name" "running" "\$(format_duration "\$uptime")" "\$mtime_str" "\$inactive_fmt" "RESTART NEEDED"
            else
                log_msg "[TRIGGER] Container \$container_name: \$reason. Restarting container..."
                if [ "\$DRY_RUN" = false ]; then
                    if docker_cmd restart "\$container_name"; then
                        log_msg "[OK] Container \$container_name restarted successfully."
                    else
                        log_msg "[ERROR] Failed to restart container \$container_name"
                    fi
                else
                    log_msg "[DRY-RUN] Would restart container \$container_name"
                fi
            fi
        else
            healthy_count=\$(( healthy_count + 1 ))
            if [ "\$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$container_name" "running" "\$(format_duration "\$uptime")" "\$mtime_str" "\$(format_duration "\$inactive_secs")" "HEALTHY (Active)"
            elif [ "\$VERBOSE" = true ]; then
                log_msg "[OK] Container \$container_name is healthy (last data \$(format_duration "\$inactive_secs") ago)"
            fi
        fi
    done

    if [ "\$STATUS_ONLY" = true ]; then
        echo "-----------------------------------------------------------------------------------------------------"
        echo "AUXILIARY PIPELINE CONTAINERS:"
    fi

    for aux in "\${AUX_CONTAINERS[@]}"; do
        local aux_status
        aux_status=\$(docker_cmd inspect --format '{{.State.Status}}' "\$aux" 2>/dev/null || echo "not found")
        if [ "\$STATUS_ONLY" = true ]; then
            printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "\$aux" "\$aux_status" "-" "-" "-" "\$([ "\$aux_status" = "running" ] && echo "HEALTHY" || echo "NEEDS ATTENTION")"
        elif [ "\$aux_status" != "running" ]; then
            log_msg "[ALERT] Pipeline container \$aux is \$aux_status! Starting container..."
            if [ "\$DRY_RUN" = false ]; then
                docker_cmd start "\$aux" 2>/dev/null || docker_cmd restart "\$aux" 2>/dev/null || true
            else
                log_msg "[DRY-RUN] Would start container \$aux"
            fi
        fi
    done

    if [ "\$STATUS_ONLY" = true ]; then
        echo "====================================================================================================="
        echo "Summary: \$healthy_count healthy, \$grace_count in grace period, \$restart_count needs restart, \$stopped_count stopped, \$missing_count missing."
        echo "Inactivity Threshold: \$(format_duration "\$TIMEOUT_SECS")"
    else
        if [ "\$restart_count" -eq 0 ] && [ "\$stopped_count" -eq 0 ]; then
            log_msg "[HEARTBEAT] All honeypots checked: healthy (\$healthy_count), grace period (\$grace_count). No restarts required."
        else
            log_msg "[SUMMARY] Watchdog run complete: \$restart_count container(s) restarted, \$stopped_count stopped container(s) handled."
        fi
    fi
}

while [[ \$# -gt 0 ]]; do
    case "\$1" in
        --status|status)
            STATUS_ONLY=true
            shift
            ;;
        --dry-run|check)
            DRY_RUN=true
            VERBOSE=true
            shift
            ;;
        --timeout)
            if [[ -n "\${2:-}" && "\$2" =~ ^[0-9]+$ ]]; then
                TIMEOUT_SECS="\$2"
                shift 2
            else
                echo "Error: --timeout requires a numeric argument (seconds)" >&2
                exit 1
            fi
            ;;
        --install)
            install_systemd
            exit 0
            ;;
        --uninstall)
            uninstall_systemd
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: \$1" >&2
            print_help
            exit 1
            ;;
    esac
done

mkdir -p "\$(dirname "\$LOCK_FILE")" 2>/dev/null || true
if command -v flock &>/dev/null; then
    exec 200>"\$LOCK_FILE"
    if ! flock -n 200; then
        echo "Another instance of honeypot-watchdog is already running. Exiting."
        exit 0
    fi
fi

run_watchdog
WATCHDOG_EOF

sudo chmod 755 "${WATCHDOG_SCRIPT}"
sudo ln -sf "${WATCHDOG_SCRIPT}" /usr/local/bin/honeypot-watchdog.sh
sudo ln -sf "${WATCHDOG_SCRIPT}" /usr/local/bin/honeypot-watchdog

log "Setup systemd service & timer untuk watchdog..."
sudo tee /etc/systemd/system/honeypot-watchdog.service > /dev/null << 'EOF'
[Unit]
Description=Honeypot Inactivity Watchdog (3-hour inactivity restart)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/honeypot-watchdog.sh
StandardOutput=journal
StandardError=journal
EOF

sudo tee /etc/systemd/system/honeypot-watchdog.timer > /dev/null << 'EOF'
[Unit]
Description=Periodic check for honeypot inactivity
Requires=honeypot-watchdog.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable honeypot-watchdog.timer
sudo systemctl restart honeypot-watchdog.timer
log "Honeypot Watchdog service dan timer diaktifkan (berjalan tiap 10 menit, timeout 3 jam)."

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
echo ""
echo "=== Status Watchdog ==="
if systemctl is-active --quiet honeypot-watchdog.timer 2>/dev/null; then
    echo "  Watchdog Timer: aktif (berjalan setiap 10 menit, timeout: 3 jam)"
else
    echo "  Watchdog Timer: tidak aktif"
fi
sudo /usr/local/bin/honeypot-watchdog.sh --status 2>/dev/null || true

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  PENTING: PORT SSH TELAH BERPINDAH KE 22888!                   ║"
echo "║  Koneksi SSH aktif Anda saat ini masih terhubung di port 22.   ║"
echo "║  Namun, untuk sesi SSH baru berikutnya, Anda WAJIB             ║"
echo "║  menggunakan port 22888:                                       ║"
echo "║  ssh -p 22888 user@ip                                          ║"
echo "║                                                                ║"
echo "║  Port 22 sekarang sepenuhnya digunakan oleh Honeypot.          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
