#!/bin/bash

USERNAME="hpot"

while true; do
    read -sp "Enter password for user $USERNAME: " PASSWORD
    echo
    read -sp "Confirm password for user $USERNAME: " PASSWORD_CONFIRM
    echo

    if [ "$PASSWORD" == "$PASSWORD_CONFIRM" ]; then
        break
    else
        echo "Passwords do not match, please try again."
    fi
done

if id "$USERNAME" &>/dev/null; then
    echo "User $USERNAME already exists."
else
    echo "Creating user $USERNAME..."
    sudo useradd -m -s /bin/bash $USERNAME
    echo "$USERNAME:$PASSWORD" | sudo chpasswd
    sudo usermod -aG sudo $USERNAME
fi

sudo su - $USERNAME -c '
cd ~
echo "Running as $(whoami)..."
wget https://raw.githubusercontent.com/sguresearcher/IHP-Honeypot/main/hpot_v2.2/script_v2.2-intel.sh
chmod +x ~/script_v2.2.sh
'
