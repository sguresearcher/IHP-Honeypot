#!/bin/bash

# Version 2.0.2 - 23 February 2024

echo '
   __ __                                 __    ____           __         __ __
  / // /___   ___  ___  __ __ ___  ___  / /_  /  _/___   ___ / /_ ___ _ / // /___  ____
 / _  // _ \ / _ \/ -_)/ // // _ \/ _ \/ __/ _/ / / _ \ (_-</ __// _  // // // -_)/ __/
/_//_/ \___//_//_/\__/ \_, // .__/\___/\__/ /___//_//_//___/\__/ \_,_//_//_/ \__//_/
                      /___//_/ BSSN - SGU WORKSHOP
'


read -p "Do you accept the terms and condition?? (y/n) " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Operation cancelled by the user."
    exit 1
fi

# Path to the flag file
FLAG_FILE="/var/script_restart_flag"

# Function to restart the script
restart_script() {
    sudo touch "$FLAG_FILE"
    sudo reboot
    exec "$0" "$@"
}

# Check if the user is root
if [ "$(id -u)" -eq 0 ]; then
    echo "This script should not be run as root. Please run as a non-root user with sudo permissions."
    exit 1
fi

# Check if the user has sudo permissions
if ! sudo -l &> /dev/null; then
    echo "You must have sudo permissions to run this script."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Update and upgrade packages
sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confnew"

# Modify /etc/security/limits.conf
LIMITS_CONF="/etc/security/limits.conf"
LIMITS_CONTENT=("root soft nofile 65536" "root hard nofile 65536" "* soft nofile 65536" "* hard nofile 65536")

for line in "${LIMITS_CONTENT[@]}"; do
    if ! grep -q "^$line" "$LIMITS_CONF"; then
        sudo bash -c "echo '$line' >> $LIMITS_CONF"
    fi
done

# Modify /etc/sysctl.conf
SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_SETTINGS=("net.core.somaxconn = 1024" "net.core.netdev_max_backlog = 5000" "net.core.rmem_max = 16777216" "net.core.wmem_max = 16777216")

for setting in "${SYSCTL_SETTINGS[@]}"; do
    key=$(echo "$setting" | cut -d '=' -f 1)
    if ! grep -q "^$key" "$SYSCTL_CONF"; then
        sudo bash -c "echo '$setting' >> $SYSCTL_CONF"
    else
        sudo sed -i "/^$key/c\\$setting" "$SYSCTL_CONF"
    fi
done

# Apply sysctl changes
sudo sysctl -p

# Main script logic
if [ -f "$FLAG_FILE" ]; then
    # Flag file exists, so continue from the restart point
    echo "Restart detected. Continuing from the restart point."
    # rm "$FLAG_FILE"

    wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb && sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb

    rvm install 2.7.6
    sudo apt install ruby-dev

    sudo gem install fluentd --no-doc

    sudo fluentd --setup ./fluent

    sudo fluent-gem install fluent-plugin-mongo

    # Ask for user confirmation
    read -p "Install Docker? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        echo "Operation cancelled by the user."
        exit 1
    fi

    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh

    sudo groupadd docker
    sudo usermod -aG docker $USER
    # newgrp docker

    sudo systemctl enable docker.service
    sudo systemctl enable containerd.service

    # Ask for user confirmation
    read -p "Install Honeypots? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        echo "Operation cancelled by the user."
        exit 1
    fi

    read -p "After this step, your SSH port will be changed into 228888. Make sure the port is opened there. Do you understand? (y/n) " -r

    echo '{ "insecure-registries":["103.175.218.193:5000"] }' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker

    sudo sed -i -e "s/#Port 22/Port 22888/g" /etc/ssh/sshd_config && sudo service sshd restart

    sudo docker pull 103.175.218.193:5000/cowrie:latest

    sudo docker volume create cowrie-var
    sudo docker volume create cowrie-etc

    sudo docker run -p 22:22/tcp -p 23:23/tcp -v cowrie-etc:/cowrie/cowrie-git/etc -v cowrie-var:/cowrie/cowrie-git/var -d --cap-drop=ALL --read-only --restart unless-stopped 103.175.218.193:5000/cowrie

    sudo apt-get install python3-pip -y
    git clone https://github.com/yevonnaelandrew/ewsposter && cd ewsposter && git checkout dionaea_fluentd && sudo pip3 install -r requirements.txt && sudo pip3 install influxdb && cd ..
    mkdir ewsposter_data ewsposter_data/log ewsposter_data/spool ewsposter_data/json
    current_dir=$(pwd)
    nodeid=$(hostname)
    sed -i "s|/home/ubuntu|$current_dir|g" ewsposter/ews.cfg
    sed -i "s|ASEAN-ID-SGU|$nodeid|g" ewsposter/ews.cfg
    cd ewsposter
    (crontab -l 2>/dev/null; echo "*/5 * * * * cd ${current_dir}/ewsposter && /usr/bin/python3 ews.py >> ews.log 2>&1") | sudo crontab -
    (crontab -l 2>/dev/null; echo "@weekly cd ${current_dir} && bash restart.sh >> restart.log 2>&1") | sudo crontab -

    cd ..
    cd fluent && sudo rm -f fluent.conf && sudo wget https://raw.githubusercontent.com/yevonnaelandrew/hpot_gui_raw/main/fluent.conf
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
    wget https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb
    sudo dpkg -i zabbix-release_6.4-1+ubuntu22.04_all.deb
    sudo apt update -y
    sudo apt install zabbix-agent2 zabbix-agent2-plugin-* -y
    sudo systemctl restart zabbix-agent2
    sudo systemctl enable zabbix-agent2

    sudo sed -i '/^ServerActive=/c\ServerActive=103.19.110.157' /etc/zabbix/zabbix_agent2.conf || echo 'ServerActive=103.19.110.157' | sudo tee -a /etc/zabbix/zabbix_agent2.conf
    sudo sed -i "/^Hostname=/c\Hostname=${replace_db}" /etc/zabbix/zabbix_agent2.conf || echo "Hostname=${replace_db}" | sudo tee -a /etc/zabbix/zabbix_agent2.conf
    sudo systemctl restart zabbix-agent2
    
else
    echo "Starting the script normally."

    sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

    sudo apt-get install software-properties-common

    sudo apt-add-repository -y ppa:rael-gc/rvm
    sudo apt-get update
    sudo apt-get install rvm -y

    sudo usermod -a -G rvm $USER

    echo 'source "/etc/profile.d/rvm.sh"' >> ~/.bashrc
    source ~/.bashrc

    read -p "You should restart the machine before continuing. Restart now? (y/n) " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        echo "Operation cancelled by the user."
        exit 1
    fi

    echo "Restarting the script..."
    restart_script "$@"
fi
