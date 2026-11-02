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

# Default configuration
DEFAULT_TIMEOUT=10800 # 3 hours in seconds
TIMEOUT_SECS="${WATCHDOG_TIMEOUT:-$DEFAULT_TIMEOUT}"
LOG_FILE="/var/log/honeypot-watchdog.log"
LOCK_FILE="/var/lock/honeypot-watchdog.lock"
MAX_LOG_SIZE=5242880 # 5 MB

# Mode flags
DRY_RUN=false
STATUS_ONLY=false
VERBOSE=false

# Honeypot definitions:
# Format: "CONTAINER_NAME:DISPLAY_NAME:DOCKER_VOLUME:RELATIVE_LOG_PATH"
HONEYPOTS=(
    "cowrie-hp:Cowrie:cowrie-var:log/cowrie/cowrie.json"
    "dionaea-hp:Dionaea:dionaea:var/lib/dionaea/dionaea.json"
    "rdpy-hp:RDPy:rdpy:rdpy.log"
    "elasticpot-hp:Elasticpot:elasticpot:elasticpot.json"
    "honeytrap-hp:Honeytrap:honeytrap-data:honeytrap.log"
    "conpot-hp:Conpot:conpot-data:conpot.json"
)

# Auxiliary pipeline containers to ensure running
AUX_CONTAINERS=("fluent-bit-hp" "nats-leaf")

# --- Helpers ---

log_msg() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local line="[$timestamp] $*"
    if [ "$STATUS_ONLY" = false ] || [ "$VERBOSE" = true ]; then
        echo "$line"
    fi
    # Append to log file if directory is writable
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
        # If interactive terminal, allow sudo prompt
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

    # Try GNU date (standard on Ubuntu)
    local epoch
    epoch=$(date -d "$iso" +%s 2>/dev/null || true)
    if [ -n "$epoch" ]; then
        echo "$epoch"
        return
    fi

    # Fallback to python3
    if command -v python3 &>/dev/null; then
        epoch=$(python3 -c "import datetime, sys; s = sys.argv[1][:19]; print(int(datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()))" "$iso" 2>/dev/null || true)
        if [ -n "$epoch" ]; then
            echo "$epoch"
            return
        fi
    fi

    # Fallback to BSD date
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
Usage: $(basename "$0") [OPTIONS]

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

Log file: $LOG_FILE
Systemd timer: honeypot-watchdog.timer
EOF
}

# --- Systemd Installation ---

install_systemd() {
    echo "Installing Honeypot Watchdog systemd service and timer..."

    local script_dest="/usr/local/bin/honeypot-watchdog.sh"
    local symlink_dest="/usr/local/bin/honeypot-watchdog"

    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: Installation requires root/sudo privileges." >&2
        exit 1
    fi

    # Copy script to /usr/local/bin
    cp -f "$0" "$script_dest"
    chmod 755 "$script_dest"
    ln -sf "$script_dest" "$symlink_dest"

    # Create systemd service
    cat <<EOF > /etc/systemd/system/honeypot-watchdog.service
[Unit]
Description=Honeypot Inactivity Watchdog (3-hour inactivity restart)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$script_dest
StandardOutput=journal
StandardError=journal
EOF

    # Create systemd timer
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

    # Reload systemd and enable timer
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
    if [ "$(id -u)" -ne 0 ]; then
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

# --- Main Watchdog Logic ---

run_watchdog() {
    local now
    now=$(date +%s)

    rotate_log

    local restart_count=0
    local healthy_count=0
    local grace_count=0
    local stopped_count=0
    local missing_count=0

    if [ "$STATUS_ONLY" = true ]; then
        echo "====================================================================================================="
        printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "CONTAINER" "STATUS" "UPTIME" "LAST DATA (MTIME)" "INACTIVE FOR" "ACTION / STATE"
        echo "====================================================================================================="
    fi

    for entry in "${HONEYPOTS[@]}"; do
        IFS=":" read -r container_name display_name volume rel_path <<< "$entry"
        local log_path
        log_path=$(get_log_path "$volume" "$rel_path")

        # 1. Check if container exists
        local exists
        exists=$(docker_cmd ps -a --filter "name=^/${container_name}$" --format '{{.Names}}' 2>/dev/null || true)
        if [ -z "$exists" ]; then
            if [ "$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$container_name" "MISSING" "-" "N/A" "-" "CONTAINER NOT FOUND"
            else
                log_msg "[WARN] Container $container_name not found on host."
            fi
            missing_count=$(( missing_count + 1 ))
            continue
        fi

        # 2. Check container status
        local c_status
        c_status=$(docker_cmd inspect --format '{{.State.Status}}' "$container_name" 2>/dev/null || echo "unknown")

        if [ "$c_status" != "running" ]; then
            stopped_count=$(( stopped_count + 1 ))
            if [ "$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$container_name" "$c_status" "-" "N/A" "-" "NEEDS START (EXITED)"
            else
                log_msg "[ALERT] Container $container_name is not running (status: $c_status). Starting container..."
                if [ "$DRY_RUN" = false ]; then
                    docker_cmd start "$container_name" || docker_cmd restart "$container_name"
                    log_msg "[OK] Container $container_name started."
                else
                    log_msg "[DRY-RUN] Would start container $container_name"
                fi
                restart_count=$(( restart_count + 1 ))
            fi
            continue
        fi

        # 3. Check container uptime
        local started_at
        started_at=$(docker_cmd inspect --format '{{.State.StartedAt}}' "$container_name" 2>/dev/null || echo "")
        local start_epoch
        start_epoch=$(iso_to_epoch "$started_at")
        local uptime=0
        if [ "$start_epoch" -gt 0 ]; then
            uptime=$(( now - start_epoch ))
            [ "$uptime" -lt 0 ] && uptime=0
        fi

        # 4. Check log file mtime
        local file_mtime
        file_mtime=$(get_file_mtime "$log_path")
        local mtime_str="No data yet"
        local inactive_secs=-1

        if [ "$file_mtime" -gt 0 ]; then
            mtime_str=$(date -d "@$file_mtime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -r "$file_mtime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$file_mtime")
            inactive_secs=$(( now - file_mtime ))
            [ "$inactive_secs" -lt 0 ] && inactive_secs=0
        fi

        # 5. Evaluate restart condition
        # GRACE PERIOD: If container has been running for less than TIMEOUT_SECS,
        # do NOT restart it (prevents infinite restart loop after fresh reboot/restart).
        if [ "$uptime" -lt "$TIMEOUT_SECS" ]; then
            grace_count=$(( grace_count + 1 ))
            local inactive_fmt="-"
            [ "$inactive_secs" -ge 0 ] && inactive_fmt=$(format_duration "$inactive_secs")
            if [ "$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$container_name" "running" "$(format_duration "$uptime")" "$mtime_str" "$inactive_fmt" "GRACE PERIOD (<$(format_duration "$TIMEOUT_SECS"))"
            elif [ "$VERBOSE" = true ]; then
                log_msg "[INFO] Container $container_name in grace period (uptime $(format_duration "$uptime") < $(format_duration "$TIMEOUT_SECS"))"
            fi
            continue
        fi

        # Container uptime is >= TIMEOUT_SECS: check data inactivity
        local needs_restart=false
        local reason=""

        if [ "$file_mtime" -eq 0 ]; then
            needs_restart=true
            reason="Log file missing or empty after running $(format_duration "$uptime")"
        elif [ "$inactive_secs" -ge "$TIMEOUT_SECS" ]; then
            needs_restart=true
            reason="No new data written for $(format_duration "$inactive_secs") (threshold: $(format_duration "$TIMEOUT_SECS"))"
        fi

        if [ "$needs_restart" = true ]; then
            restart_count=$(( restart_count + 1 ))
            if [ "$STATUS_ONLY" = true ]; then
                local inactive_fmt="never"
                [ "$inactive_secs" -ge 0 ] && inactive_fmt=$(format_duration "$inactive_secs")
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$container_name" "running" "$(format_duration "$uptime")" "$mtime_str" "$inactive_fmt" "RESTART NEEDED"
            else
                log_msg "[TRIGGER] Container $container_name: $reason. Restarting container..."
                if [ "$DRY_RUN" = false ]; then
                    if docker_cmd restart "$container_name"; then
                        log_msg "[OK] Container $container_name restarted successfully."
                    else
                        log_msg "[ERROR] Failed to restart container $container_name"
                    fi
                else
                    log_msg "[DRY-RUN] Would restart container $container_name"
                fi
            fi
        else
            healthy_count=$(( healthy_count + 1 ))
            if [ "$STATUS_ONLY" = true ]; then
                printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$container_name" "running" "$(format_duration "$uptime")" "$mtime_str" "$(format_duration "$inactive_secs")" "HEALTHY (Active)"
            elif [ "$VERBOSE" = true ]; then
                log_msg "[OK] Container $container_name is healthy (last data $(format_duration "$inactive_secs") ago)"
            fi
        fi
    done

    # Check auxiliary pipeline containers
    if [ "$STATUS_ONLY" = true ]; then
        echo "-----------------------------------------------------------------------------------------------------"
        echo "AUXILIARY PIPELINE CONTAINERS:"
    fi

    for aux in "${AUX_CONTAINERS[@]}"; do
        local aux_status
        aux_status=$(docker_cmd inspect --format '{{.State.Status}}' "$aux" 2>/dev/null || echo "not found")
        if [ "$STATUS_ONLY" = true ]; then
            printf "%-15s %-10s %-12s %-22s %-14s %-20s\n" "$aux" "$aux_status" "-" "-" "-" "$([ "$aux_status" = "running" ] && echo "HEALTHY" || echo "NEEDS ATTENTION")"
        elif [ "$aux_status" != "running" ]; then
            log_msg "[ALERT] Pipeline container $aux is $aux_status! Starting container..."
            if [ "$DRY_RUN" = false ]; then
                docker_cmd start "$aux" 2>/dev/null || docker_cmd restart "$aux" 2>/dev/null || true
            else
                log_msg "[DRY-RUN] Would start container $aux"
            fi
        fi
    done

    if [ "$STATUS_ONLY" = true ]; then
        echo "====================================================================================================="
        echo "Summary: $healthy_count healthy, $grace_count in grace period, $restart_count needs restart, $stopped_count stopped, $missing_count missing."
        echo "Inactivity Threshold: $(format_duration "$TIMEOUT_SECS")"
    else
        if [ "$restart_count" -eq 0 ] && [ "$stopped_count" -eq 0 ]; then
            log_msg "[HEARTBEAT] All honeypots checked: healthy ($healthy_count), grace period ($grace_count). No restarts required."
        else
            log_msg "[SUMMARY] Watchdog run complete: $restart_count container(s) restarted, $stopped_count stopped container(s) handled."
        fi
    fi
}

# --- CLI Argument Parsing ---

while [[ $# -gt 0 ]]; do
    case "$1" in
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
            if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
                TIMEOUT_SECS="$2"
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
            echo "Unknown option: $1" >&2
            print_help
            exit 1
            ;;
    esac
done

# Run main logic with file lock to prevent concurrent overlapping executions
mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
if command -v flock &>/dev/null; then
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "Another instance of honeypot-watchdog is already running. Exiting."
        exit 0
    fi
fi

run_watchdog
