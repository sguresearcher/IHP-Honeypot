#!/bin/bash
current_dir=$(pwd)
sudo apt update
sudo apt install jq -y

sudo mkdir -p /home/ubuntu/fluent/tmplog
sudo mkdir -p /home/ubuntu/fluent/offset

sudo chown -R ubuntu:ubuntu /home/ubuntu/fluent

curl -o /home/ubuntu/fluent/log_down_handler.sh https://raw.githubusercontent.com/sguresearcher/IHP-Honeypot/main/log_down_handler.sh
chmod +x /home/ubuntu/fluent/log_down_handler.sh
(crontab -l 2>/dev/null; echo "* * * * * ${current_dir}/fluent/tmplog/log_down_handler.sh") | crontab -

echo "DLP Installation Finished."
