#!/bin/bash
#
# replay-attacks.sh — Offline pcap replay through Suricata
# Uses suricata -r to process pcaps without needing live capture
#
# Usage:
#   ./replay-attacks.sh                 # Process all pcaps
#   ./replay-attacks.sh lokibot         # Process single pcap
#   ./replay-attacks.sh list            # List available pcaps
#   ./replay-attacks.sh check           # Check alerts in ClickHouse

set -e

BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_DIR="$BASEDIR/pcaps"
LOG_DIR="$BASEDIR/suricata"
EVE_JSON="$LOG_DIR/eve.json"
CLICKHOUSE_URL="http://localhost:8123"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_suricata_config() {
    if [ ! -f /etc/suricata/suricata.yaml ]; then
        echo -e "${RED}Suricata config not found at /etc/suricata/suricata.yaml${NC}"
        exit 1
    fi
}

list_pcaps() {
    echo "Available pcaps in $PCAP_DIR:"
    echo ""
    for f in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
        if [ -f "$f" ]; then
            size=$(du -h "$f" | cut -f1)
            name=$(basename "$f")
            echo "  $name  ($size)"
        fi
    done
}

replay_pcap() {
    local pcap="$1"
    local name=$(basename "$pcap")

    echo -e "${YELLOW}[*] Processing: $name${NC}"

    # Save current eve.json so we can diff later
    if [ -f "$EVE_JSON" ]; then
        local before=$(wc -l < "$EVE_JSON" 2>/dev/null || echo 0)
    else
        local before=0
    fi

    # Run suricata in offline mode with local config
    suricata -r "$pcap" \
      -c "$BASEDIR/suricata/suricata-replay.yaml" \
      -l "$LOG_DIR" -k none 2>&1 | tail -5

    local after=$(wc -l < "$EVE_JSON" 2>/dev/null || echo 0)
    local new=$((after - before))

    echo -e "${GREEN}[+] $name done — $new new lines in eve.json${NC}"

    # Count alerts
    if [ "$new" -gt 0 ]; then
        local alerts=$(tail -n "$new" "$EVE_JSON" | python3 -c "import sys,json; c=0; [exec('try: c+=1 if j.get(\"event_type\")==\"alert\" else 0\nexcept:pass') for j in [json.loads(l) for l in sys.stdin]]; print(c)" 2>/dev/null || echo "?")
        echo -e "${GREEN}    -> $alerts alerts generated${NC}"
    fi

    echo ""
}

replay_all() {
    for f in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
        if [ -f "$f" ]; then
            replay_pcap "$f"
        fi
    done
}

check_clickhouse() {
    local auth="soc_user:changeme"
    echo "Checking ClickHouse for alerts..."
    echo ""

    # Total alerts
    echo "=== Total alerts in soc.suricata_alerts ==="
    curl -s -u "$auth" "$CLICKHOUSE_URL" --data "SELECT count(*) FROM soc.suricata_alerts" 2>/dev/null || echo "ClickHouse not reachable"

    echo ""
    echo "=== Top alert signatures ==="
    curl -s -u "$auth" "$CLICKHOUSE_URL" --data "SELECT alert_signature, count(*) as cnt FROM soc.suricata_alerts GROUP BY alert_signature ORDER BY cnt DESC LIMIT 10" 2>/dev/null || true

    echo ""
    echo "=== Alerts by severity ==="
    curl -s -u "$auth" "$CLICKHOUSE_URL" --data "SELECT alert_severity, count(*) as cnt FROM soc.suricata_alerts GROUP BY alert_severity ORDER BY alert_severity" 2>/dev/null || true

    echo ""
    echo "=== Recent alerts ==="
    curl -s -u "$auth" "$CLICKHOUSE_URL" --data "SELECT timestamp, alert_signature, src_ip, dest_ip FROM soc.suricata_alerts ORDER BY timestamp DESC LIMIT 5" 2>/dev/null || true

    echo ""
    echo "=== Grafana Dashboards ==="
    echo "  Alerts Overview:   http://localhost:3000/d/soc-alerts-overview/soc-e28094-alerts-overview"
    echo "  Incident Timeline: http://localhost:3000/d/soc-incident-timeline/soc-e28094-incident-timeline-and-drill-down"
    echo "  Threat Intel:      http://localhost:3000/d/soc-threat-intel/soc-e28094-threat-intelligence-and-ioc-view"
    echo "  Login: admin / admin"
}

case "${1:-all}" in
    list)
        list_pcaps
        ;;
    check)
        check_clickhouse
        ;;
    all)
        check_suricata_config
        replay_all
        echo -e "${GREEN}All pcaps processed!${NC}"
        echo "Run './replay-attacks.sh check' to see alerts in ClickHouse"
        ;;
    *)
        check_suricata_config
        if [ -f "$PCAP_DIR/$1.pcap" ]; then
            replay_pcap "$PCAP_DIR/$1.pcap"
        elif [ -f "$PCAP_DIR/$1.pcapng" ]; then
            replay_pcap "$PCAP_DIR/$1.pcapng"
        elif [ -f "$PCAP_DIR/$1" ]; then
            replay_pcap "$PCAP_DIR/$1"
        else
            echo -e "${RED}Unknown pcap: $1${NC}"
            list_pcaps
            exit 1
        fi
        echo "Run './replay-attacks.sh check' to see alerts in ClickHouse"
        ;;
esac
