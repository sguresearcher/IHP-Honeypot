#!/bin/bash

# Version 2.0.3 (compat) - 05 Oct 2025
# Perubahan utama: ganti registry ke Docker Hub andiparada/<image>:v2.1

echo '
   __ __                                 __    ____           __         __ __
  / // /___   ___  ___  __ __ ___  ___  / /_  /  _/___   ___ / /_ ___ _ / // /___  ____
 / _  // _ \ / _ \/ -_)/ // // _ \/ _ \/ __/ _/ / / _ \ (_-</ __// _  // // // -_)/ __/
/_//_/ \___//_//_/\__/ \_, // .__/\___/\__/ /___//_//_//___/\__/ \_,_//_//_/ \__//_/
                      /___//_/
'

read -p "Do you accept the terms and condition?? (y/n) " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Operation cancelled by the user."
    exit 1
fi

# ----- konstanta -----
FLAG_FILE="/var/script_restart_flag"

# ----- fungsi -----
restart_script() {
    sudo touch "$FLAG_FILE"
    sudo reboot
    exec "$0" "$@"
}

# Check not root
if [ "$(id -u)" -eq 0 ]; then
    echo "This script should not be run as root. Please run as a non-root user with sudo permissions."
    exit 1
fi

# Check sudo
if ! sudo -l &> /dev/null; then
    echo "You must have sudo permissions to run this script."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confnew"

LIMITS_CONF="/etc/security/limits.conf"
LIMITS_CONTENT=("root soft nofile 65536" "root hard nofile 65536" "* soft nofile 65536" "* hard nofile 65536")
for line in "${LIMITS_CONTENT[@]}"; do
    if ! grep -q "^$line" "$LIMITS_CONF"; then
        echo "$line" | sudo tee -a "$LIMITS_CONF" >/dev/null
    fi
done

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_SETTINGS=("net.core.somaxconn = 1024" "net.core.netdev_max_backlog = 5000" "net.core.rmem_max = 16777216" "net.core.wmem_max = 16777216")
for setting in "${SYSCTL_SETTINGS[@]}"; do
    key=$(echo "$setting" | cut -d '=' -f 1)
    if ! grep -q "^$key" "$SYSCTL_CONF"; then
        echo "$setting" | sudo tee -a "$SYSCTL_CONF" >/dev/null
    else
        sudo sed -i "/^$key/c\\$setting" "$SYSCTL_CONF"
    fi
done
sudo sysctl -p

# --------- MAIN LOGIC ----------
if [ -f "$FLAG_FILE" ]; then
    echo "Restart detected. Continuing from the restart point."
    # rm "$FLAG_FILE"  # (tetap dikomentari seperti script lama)

    wget -q http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb && sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb || true

    rvm install 2.7.6 || true
    sudo apt install -y ruby-dev
    sudo gem install fluentd --no-doc
    sudo fluentd --setup ./fluent || true
    sudo fluent-gem install fluent-plugin-mongo

    # Install Docker
    read -p "Install Docker? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operation cancelled by the user."
        exit 1
    fi
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo groupadd docker 2>/dev/null || true
    sudo usermod -aG docker $USER
    sudo systemctl enable docker.service
    sudo systemctl enable containerd.service

    # Install Honeypots
    read -p "Install Honeypots? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operation cancelled by the user."
        exit 1
    fi

    read -p "After this step, your SSH port will be changed into 22888. Make sure the port is opened there. Do you understand? (y/n) " -r

    sudo sed -i -e "s/^#*Port .*/Port 22888/g" /etc/ssh/sshd_config && (sudo systemctl restart ssh || sudo service ssh restart)

    sudo docker pull andiparada/cowrie:v2.1
    sudo docker pull andiparada/conpot:v2.1
    sudo docker pull andiparada/rdpy:v2.1
    sudo docker pull andiparada/elasticpot:v2.1
    sudo docker pull andiparada/dionaea:v2.1
    sudo docker pull andiparada/honeytrap:v2.1

    sudo docker volume create cowrie-var
    sudo docker volume create cowrie-etc
    sudo mkdir -p /var/lib/docker/volumes/rdpy /var/lib/docker/volumes/rdpy/_data
    sudo docker volume create gridpot
    sudo mkdir -p /var/lib/docker/volumes/elasticpot /var/lib/docker/volumes/elasticpot/_data

    sudo docker run -p 22:22/tcp -p 23:23/tcp \
      -v cowrie-etc:/cowrie/cowrie-git/etc \
      -v cowrie-var:/cowrie/cowrie-git/var \
      -d --cap-drop=ALL --read-only --restart unless-stopped \
      andiparada/cowrie:v2.1

    sudo docker run -it -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 -p 443:443 -p 445:445 \
      -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 3306:3306 -p 5060:5060 -p 5060:5060/udp \
      -p 5061:5061 -p 11211:11211 -v dionaea:/opt/dionaea \
      -d --restart unless-stopped \
      andiparada/dionaea:v2.1

    sudo docker run -it -p 3389:3389 -v rdpy:/var/log \
      -d --restart unless-stopped \
      andiparada/rdpy:v2.1 \
      /bin/sh -c 'python /rdpy/bin/rdpy-rdphoneypot.py -l 3389 /rdpy/bin/1 >> /var/log/rdpy.log'

    sudo docker run -it -p 9200:9200/tcp -v elasticpot:/elasticpot/log \
      -d --restart unless-stopped \
      andiparada/elasticpot:v2.1 \
      /bin/sh -c 'cd elasticpot; python3 elasticpot.py'

    sudo docker run -it -p 2222:2222 -p 8545:8545 -p 5900:5900 -p 25:25 -p 5037:5037 -p 631:631 -p 389:389 -p 6379:6379 \
      -v honeytrap:/home -d --restart unless-stopped \
      andiparada/honeytrap:v2.1

    sudo docker run -d --restart always -v conpot:/data \
      -p 8000:8800 -p 10201:10201 -p 5020:5020 -p 16100:16100/udp -p 47808:47808/udp -p 6230:6230/udp \
      -p 2121:2121 -p 6969:6969/udp -p 44818:44818 \
      andiparada/conpot:v2.1

    sudo apt-get install -y python3-pip
    if [ ! -d ewsposter ]; then
      git clone https://github.com/yevonnaelandrew/ewsposter
    fi
    cd ewsposter && git checkout dionaea_fluentd || true
    sudo pip3 install -r requirements.txt && sudo pip3 install influxdb && cd ..
    mkdir -p ewsposter_data ewsposter_data/log ewsposter_data/spool ewsposter_data/json
    current_dir=$(pwd)
    nodeid=$(hostname)
    sed -i "s|/home/ubuntu|$current_dir|g" ewsposter/ews.cfg
    sed -i "s|ASEAN-ID-SGU|$nodeid|g" ewsposter/ews.cfg
    cd ewsposter
    (crontab -l 2>/dev/null; echo "*/5 * * * * cd ${current_dir}/ewsposter && /usr/bin/python3 ews.py >> ews.log 2>&1") | sudo crontab -
    (crontab -l 2>/dev/null; echo "@weekly cd ${current_dir} && bash restart.sh >> restart.log 2>&1") | sudo crontab -
    cd ..
    cd fluent && sudo rm -f fluent.conf && sudo wget -q https://raw.githubusercontent.com/yevonnaelandrew/hpot_gui_raw/main/fluent.conf
    echo "User id untuk database:"
    read replace_id
    echo "Password untuk database:"
    read replace_pass
    echo "Nama tenant/db (masukkan persis sesuai yang dikasih):"
    read replace_db
    sudo sed -i "s/fillthename/$replace_id/g" fluent.conf
    sudo sed -i "s/fillthepass/$replace_pass/g" fluent.conf
    sudo sed -i "s/fillthedb/$replace_db/g" fluent.conf
    cd

    wget -q https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb
    sudo dpkg -i zabbix-release_6.4-1+ubuntu22.04_all.deb
    sudo apt update -y
    sudo apt install -y zabbix-agent2 zabbix-agent2-plugin-*
    sudo systemctl restart zabbix-agent2
    sudo systemctl enable zabbix-agent2

    sudo sed -i '/^ServerActive=/c\ServerActive=103.19.110.157' /etc/zabbix/zabbix_agent2.conf || echo 'ServerActive=103.19.110.157' | sudo tee -a /etc/zabbix/zabbix_agent2.conf
    sudo sed -i "/^Hostname=/c\Hostname=${replace_db}" /etc/zabbix/zabbix_agent2.conf || echo "Hostname=${replace_db}" | sudo tee -a /etc/zabbix/zabbix_agent2.conf
    sudo systemctl restart zabbix-agent2

else
    echo "Starting the script normally."
    # ====== PATCH: cek dulu swapfile biar tidak error ======
    if ! swapon --show | grep -q '^/swapfile'; then
      if [ ! -f /swapfile ]; then
        sudo fallocate -l 1G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=1024
      fi
      sudo chmod 600 /swapfile
      sudo mkswap /swapfile 2>/dev/null || true
      sudo swapon /swapfile 2>/dev/null || true
      if ! grep -q '^/swapfile ' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
      fi
    else
      echo "[i] Swapfile already active. Skipping swap creation."
    fi
    # ====== END PATCH ======

    sudo apt-get install -y software-properties-common
    sudo apt-add-repository -y ppa:rael-gc/rvm
    sudo apt-get update -y
    sudo apt-get install -y rvm
    sudo usermod -a -G rvm $USER
    echo 'source "/etc/profile.d/rvm.sh"' >> ~/.bashrc
    source ~/.bashrc || true

    read -p "You should restart the machine before continuing. Restart now? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operation cancelled by the user."
        exit 1
    fi

    echo "Restarting the script..."
    restart_script "$@"
fi
