# Honeypot Installer v2.3 - User Guide

This guide covers the prerequisites, installation process, and post-installation steps for the Honeypot Installer v2.3 (TLS Edition).

## Requirements

Before running the script, ensure you have the following:
1. A Linux system (Ubuntu/Debian) : Ubuntu 24.04.4 LTS
2. IP VPS Public and access to internet for fetching latest updates and packages
3. Minimum Requirement : 1 CPU Core, 1GB RAM and 15GB Storage
4. VPS Recommended: 2 CPU Core, 2GB RAM and 30GB Storage

## Description

The `installation-script-2.3.sh` and `id_installation-script-2.3.sh`(indonesian language)  script automates the deployment of a comprehensive honeypot system. It is designed to be idempotent, meaning it can be run multiple times safely without causing unintended side effects.

**Key Features:**
- **Honeypots Included:** Cowrie, Dionaea, RDPy, Elasticpot, Honeytrap, Conpot.
- **Data Shipping:** Uses Fluent Bit to parse and ship honeypot logs.
- **NATS Integration:** Configures a NATS Leaf Node to connect to a central NATS Hub, supporting JWT authentication and optional TLS encryption.
- **Monitoring:** Installs and configures Zabbix Agent 2.
- **System Hardening:** Changes the default SSH port, configures system limits (sysctl/limits.conf), and sets up swap space.

---

## Pre-Installation Requirements

Before running the script, ensure you have the following ready:

1. **User Privileges:** You must run the script as a regular user with `sudo` privileges. **Do NOT run the script as the `root` user.**
2. **NATS Hub Information:**
   - The IP address(es) of your NATS Hub.
   - The port number for the NATS Hub (default is usually `4222`).
3. **NATS Credentials:** Have your NATS JWT Credentials file (`.creds`) content ready to copy and paste.
4. **TLS Configuration:**
   - Have your CA Certificate (`.pem`) content ready to paste, or know its absolute path on the server.
5. **Zabbix Information:** Decide on a Zabbix Hostname for this virtual machine.
6. **Firewall:** **CRITICAL:** The script will change the SSH port to **`22888`**. Ensure your firewall (e.g., UFW, cloud provider security groups) allows incoming TCP traffic on port `22888` before you start, otherwise you will lose access to the server.

---

## During Installation

The installation happens in two phases. A system reboot is required between Phase 1 and Phase 2.

### Phase 1: System Preparation

1. Execute the script:
   ```bash
   ./installation-script-2.3.sh
   ```
2. Accept the terms and conditions by typing `y`.
3. Provide the required configuration inputs when prompted:
   - **NATS Hub IPs:** Enter comma-separated IPs or press Enter for the default.

   - **NATS Hub Port:** Enter the port or press Enter for the default.
   - **NATS JWT Credentials:** Paste the entire contents of your `.creds` file. When finished pasting, type `EOF` on a new line and press Enter.
   - **TLS Configuration:** Choose `Y`, choose whether to paste the CA certificate inline (`1`) or provide a file path (`2`). If this the first time you deploy the honeypot, you prefer to choose (`1`). If pasting inline, end with `EOF` on a new line and press Enter. After that, press Enter again if you want to skip TLS verification (default is `N`, recommended).
   - **Zabbix Hostname:** Enter the hostname for this VM.
4. The script will update packages, configure system limits, set up a 1GB swap file, and set a flag file for Phase 2.
5. **Reboot Prompt:** The script will ask to reboot the system. Type `y`.

### Phase 2: Deploying Services

1. After the server reboots, reconnect via SSH. **Remember to use the new SSH port (`22888`) if it was changed!**
   ```bash
   ssh -p 22888 your_user@your_server_ip
   ```
   *(Note: adjust the port and IP address if needed, maybe u'r first time it's still port 22 by default)*

2. Run the installation script again:
   ```bash
   ./installation-script-2.3.sh
   ```
3. The script will automatically detect that Phase 1 is complete and proceed with Phase 2. It will:
   - Install Docker (if not present).
   - Add the insecure registry configuration.
   - Pull the necessary Docker images.
   - Create Docker volumes.
   - Start all honeypot containers.
   - Configure and start the NATS Leaf Node.
   - Configure and start Fluent Bit.
   - Install and configure Zabbix Agent 2.

---

## Post-Installation

Once Phase 2 completes, the script will output a final status summary. Review this carefully.

1. **Verify Services:**
   Check the output of `=== Running Containers ===`. You should see the following containers listed with an `Up` and `Healthy` status:
   - `cowrie-hp`
   - `dionaea-hp`
   - `rdpy-hp`
   - `elasticpot-hp`
   - `honeytrap-hp`
   - `conpot-hp`
   - `nats-leaf`
   - `fluent-bit-hp`

2. **Verify NATS Connection:**
   Review the `=== NATS Leaf Connection ===` section in the output. Look for lines indicating a successful connection to the NATS Hub (e.g., `connected`). If there are TLS or credential errors, they will appear here.
   To check manually later:
   ```bash
   sudo docker logs nats-leaf
   ```

3. **Verify Log Shipping:**
   Check the `=== Fluent Bit Status ===` output to ensure it started without critical errors.
   To check manually later:
   ```bash
   sudo docker logs fluent-bit-hp
   ```

4. **Verify Zabbix Agent:**
   Ensure the Zabbix Agent is running and active:
   ```bash
   systemctl status zabbix-agent2
   ```

5. **Subsequent Logins:**
   Remember that your SSH port is now `22888`. All future SSH connections must specify this port.

6. **Idempotency:**
   If a container stops or configuration needs to be refreshed (like updating NATS credentials), you can safely run the script again (`./installation-script-2.3.sh`). It will skip steps that are already completed and recreate containers with the latest configuration.

Note* :
If you want to go back to phase 1, use this command: 
```bash
./installation-script-2.3.sh --phase1
```

# Honeypot Port Mapping

Service exposure across deployed honeypot sensors.

| No | Honeypot Name | Port | Transport |
|---:|---------------|------|-----------|
| 01 | Cowrie | 22/tcp | TCP |
| 02 | Cowrie | 23/tcp | TCP |
| 03 | Dionaea | 21 | TCP |
| 04 | Dionaea | 42 | TCP |
| 05 | Dionaea | 69/udp | UDP |
| 06 | Dionaea | 80 | TCP |
| 07 | Dionaea | 135 | TCP |
| 08 | Dionaea | 443 | TCP |
| 09 | Dionaea | 445 | TCP |
| 10 | Dionaea | 1433 | TCP |
| 11 | Dionaea | 1723 | TCP |
| 12 | Dionaea | 1883 | TCP |
| 13 | Dionaea | 3306 | TCP |
| 14 | Dionaea | 5060 | TCP |
| 15 | Dionaea | 5060/udp | UDP |
| 16 | Dionaea | 5061 | TCP |
| 17 | Dionaea | 11211 | TCP |
| 18 | RDPY | 3389 | TCP |
| 19 | Honeytrap | 2222 | TCP |
| 20 | Honeytrap | 8545 | TCP |
| 21 | Honeytrap | 5900 | TCP |
| 22 | Honeytrap | 25 | TCP |
| 23 | Honeytrap | 5037 | TCP |
| 24 | Honeytrap | 631 | TCP |
| 25 | Honeytrap | 389 | TCP |
| 26 | Honeytrap | 6379 | TCP |
| 27 | Conpot | 8000:8800 | TCP |
| 28 | Conpot | 10201 | TCP |
| 29 | Conpot | 5020 | TCP |
| 30 | Conpot | 16100/udp | UDP |
| 31 | Conpot | 47808/udp | UDP |
| 32 | Conpot | 6230/udp | UDP |
| 33 | Conpot | 2121 | TCP |
| 34 | Conpot | 6969/udp | UDP |
| 35 | Conpot | 44818 | TCP |
| 36 | Elasticpot | 9200/tcp | TCP |

_36 entries · TCP / UDP services_