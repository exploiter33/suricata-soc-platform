# Suricata SOC Platform

> A hands-on SOC analyst portfolio project demonstrating a modern SIEM pipeline centered around Suricata IDS/IPS, with real-time dashboards in Grafana, automated threat response via n8n, and structured incident response playbooks.

![Dashboard Preview](evidence/alerts-overview.png)

---

## Architecture

```
Suricata (host) ──→ eve.json
                       │
                  [Vector]  ──→  [ClickHouse]  ←── [Grafana]
                                    │
                               [n8n SOAR]
                          (auto-block, Slack,
                           ticket creation)
```

| Component | Purpose | Deployment |
|---|---|---|
| **Suricata** | Network IDS/IPS — generates alert, HTTP, DNS logs | Running on host |
| **Vector** | Log shipper — reads `eve.json`, parses, sends to ClickHouse | Docker |
| **ClickHouse** | Column-oriented analytics DB — stores all alert data | Docker |
| **Grafana** | Visualization — 3 pre-built SOC dashboards with ClickHouse queries | Docker |
| **n8n** | SOAR automation — auto-block IPs, Slack alerts, create tickets | Docker |

---

## Features

### SOC Dashboards (Grafana)
- **Alerts Overview** — severity breakdown, top signatures, alert timeline, top source IPs, protocol distribution
- **Threat Intelligence** — suspicious DNS queries, malware downloads, uncommon outbound connections
- **Incident Timeline** — 7-day alert heatmap, event drill-down, source IP clustering

### Detection Rules (Suricata)
- **`sid:1000001`** — SSH brute force threshold (5 failures in 60s)
- **`sid:1000002`** — Outbound beacon on non-standard ports
- **`sid:1000003`** — ICMP flood / large packet detection
- **`sid:1000004-6`** — DNS queries to suspicious TLDs (.xyz / .top / .tk)
- **`sid:1000007`** — HTTP executable download detection

### SOAR Workflows (n8n)
- **Auto-block IP** — receives webhook, runs iptables block, notifies Slack
- **Slack Escalation** — formats alert data and posts to security channel
- **Ticket Creation** — generates incident ticket from high-severity alerts

### Automation Tools
- `tools/suricata-rule-manager.py` — enable/disable/test rules from CLI
- `tools/ioc-extractor.py` — pull IOCs from eve.json by time window and severity
- `tools/report-generator.py` — query ClickHouse and produce executive summary report

### Incident Response Playbooks
- `playbooks/port-scan.md` — triage, containment, escalation for scan events (T1046)
- `playbooks/ssh-brute-force.md` — handle credential stuffing and SSH brute force (T1110)
- `playbooks/malware-c2-beacon.md` — detect and contain command & control traffic (T1071)

### Threat Hunting Queries
All queries mapped to MITRE ATT&CK framework:
- `queries/port-scan-detection.sql` — T1046
- `queries/brute-force-spike.sql` — T1110
- `queries/suspicious-traffic.sql` — T1071, T1105, T1568
- `queries/MITRE-MAPPING.md` — full technique-to-detection mapping table

### Attack Simulation
- `scripts/simulate-attacks.sh` — lightweight nmap, hydra, ping, curl probes
- Generates real alerts in Suricata for live demo screenshots

---

## Prerequisites

- **OS:** Linux (tested on Ubuntu / Kali)
- **Suricata** installed and running: `sudo apt install suricata`
- **Docker + Docker Compose:** `sudo apt install docker.io docker-compose-v2`
- **Python 3.8+** with `clickhouse-driver` (for report generator)

---

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/YOUR_USER/suricata-soc-platform.git
cd suricata-soc-platform
cp .env.example .env
# Edit .env with your passwords if desired
```

### 2. Deploy Docker Stack

```bash
docker compose up -d
```

This starts: ClickHouse, Vector, Grafana (port 3000), n8n (port 5678).

### 3. Load Custom Suricata Rules

If running live Suricata:
```bash
sudo cp suricata/custom.rules /etc/suricata/rules/
# Add to /etc/suricata/suricata.yaml under rule-files:
#   - custom.rules
sudo systemctl restart suricata
```

### 4. Process PCAPs (Offline Replay)

No live Suricata setup needed. Process the included pcap files with:

```bash
# Process all pcaps at once:
./scripts/replay-attacks.sh

# Or process a single pcap:
./scripts/replay-attacks.sh pcaps/lokibot.pcap
```

This runs `suricata -r` offline against each pcap and sends results through Vector → ClickHouse.

### 5. Live Attack Simulation (Optional)

If you have Suricata running live on the host:

```bash
chmod +x scripts/simulate-attacks.sh
sudo ./scripts/simulate-attacks.sh all
```

### 6. Open Grafana

Navigate to [http://localhost:3000](http://localhost:3000)
- Login: `admin` / `admin` (or whatever you set in `.env`)
- Go to Dashboards → SOC — Alerts Overview

### 7. Generate a Report

```bash
pip install clickhouse-driver
python tools/report-generator.py --hours 24
```

---

## Running the Tools

```bash
# List all custom Suricata rules
sudo python tools/suricata-rule-manager.py list

# Disable a rule
sudo python tools/suricata-rule-manager.py disable 1000007

# Test if a rule fired recently
sudo python tools/suricata-rule-manager.py test 1000001

# Extract IOCs from last 48h (severity 1-2)
python tools/ioc-extractor.py --last-h 48 --min-severity 2

# Generate executive report
python tools/report-generator.py --hours 168 --output report.md
```

---

## Evidence Gallery

| Detection | Screenshot |
|---|---|
| **Alerts Overview** | ![Alerts Overview](evidence/alerts-overview.png) |
| **Incident Timeline** | ![Incident Timeline](evidence/incident-timeline.png) |
| **Threat Intelligence** | ![Threat Intel](evidence/threat-intel.png) |
| **Detection Logic** | [detection-logic.md](evidence/detection-logic.md) |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| Reconnaissance | T1046, T1595 |
| Credential Access | T1110, T1110.001, T1110.002 |
| Command & Control | T1071.001, T1071.004, T1568 |
| Defense Evasion | T1572 |
| Execution | T1105 (via tool download monitoring) |

Full mapping in [queries/MITRE-MAPPING.md](queries/MITRE-MAPPING.md).

---

## Skills Demonstrated

| Skill | Evidence in This Project |
|---|---|
| **SIEM Operations** | ClickHouse + Grafana pipeline, log ingestion, dashboard creation |
| **Detection Engineering** | 7 custom Suricata rules + SQL hunting queries |
| **Incident Response** | 3 structured IR playbooks (NIST 800-61 style) |
| **MITRE ATT&CK** | Every detection mapped to technique IDs |
| **Automation / SOAR** | n8n workflows for block/escalate/ticket |
| **Forensics / IOC** | IOC extractor from raw eve.json |
| **Reporting** | Executive summary generator |
| **Log Analysis** | Vector pipeline parsing JSON logs to structured tables |
| **Linux / Docker** | Full compose-based deployment |

---

## Future Enhancements

- [ ] Integrate with MISP for automated threat intel feed ingestion
- [ ] Add Velociraptor for endpoint artifact collection
- [ ] Deploy Sigma rule converter for additional detection logic
- [ ] Add TheHive for case management integration
- [ ] Implement email alerting via n8n

---

## License

MIT
