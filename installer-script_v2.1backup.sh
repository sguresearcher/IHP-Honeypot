#!/bin/bash

# Nama user
USERNAME="hpot"

# Meminta password dari pengguna dengan konfirmasi
while true; do
    read -sp "Masukkan password untuk user $USERNAME: " PASSWORD
    echo
    read -sp "Konfirmasi password untuk user $USERNAME: " PASSWORD_CONFIRM
    echo

    if [ "$PASSWORD" == "$PASSWORD_CONFIRM" ]; then
        break
    else
        echo "Password tidak cocok, silakan coba lagi."
    fi
done

# Memeriksa apakah user sudah ada, jika tidak, baru dibuat
if id "$USERNAME" &>/dev/null; then
    echo "User $USERNAME sudah ada."
else
    echo "Membuat user $USERNAME..."
    sudo useradd -m -s /bin/bash $USERNAME
    echo "$USERNAME:$PASSWORD" | sudo chpasswd
    sudo usermod -aG sudo $USERNAME
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$USERNAME
fi

# Beralih ke user hpot, download, dan jalankan script baru
sudo su - $USERNAME -c '
cd ~
echo "Menjalankan sebagai $(whoami)..."

# Download script baru
wget https://raw.githubusercontent.com/sguresearcher/IHP-Honeypot/main/script_v2.1.sh

# Pastikan script yang diunduh dapat dieksekusi
chmod +x ~/script_v2.1.sh
'
