#!/bin/bash
current_dir=$(pwd)
current_user=$(whoami)

sudo apt update
sudo apt install jq -y

sudo mkdir -p "${current_dir}/fluent/tmplog"
sudo mkdir -p "${current_dir}/fluent/offset"

sudo chown -R ${current_user}:${current_user} "${current_dir}/fluent"

curl -o ${current_dir}/fluent/tmplog/log_down_handler.sh https://raw.githubusercontent.com/sguresearcher/IHP-Honeypot/main/log_down_handler.sh
chmod +x ${current_dir}/fluent/tmplog/log_down_handler.sh

(sudo crontab -l 2>/dev/null; echo "* * * * * cd ${current_dir}/fluent/tmplog && bash log_down_handler.sh") | sudo crontab -

echo "DLP Installation Finished."

