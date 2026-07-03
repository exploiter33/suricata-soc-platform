# Portfolio Walkthrough — Lokibot C2 Beacon Detection & Response

> End-to-end incident handling following SOC Analyst workflow: **Detect → Investigate → Extract IOCs → Enrich → Respond**

---

## Scenario

A machine on the internal network contacts a known malware distribution endpoint over HTTP to download `update.exe`. Suricata IDS detects the outbound connection and the executable download, triggering a high-severity alert.

---

## 1. Detection — Suricata Custom Rule

**Rule `sid:1000007` fires when an HTTP response contains an executable download:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"THREAT: Potential Malware Download (.exe)";
  content:".exe"; http_uri; nocase;
  classtype:trojan-activity; sid:1000007; rev:1;
)
```

**Evidence:** `suricata/custom.rules` — rule logic  
**Raw data:** `suricata/eve.json` — alert event with src_ip, dest_ip, url, signature

---

## 2. Investigation — Grafana Dashboards

### Alerts Overview Dashboard

Open Grafana → **SOC — Alerts Overview**

| Panel | What It Shows |
|---|---|
| Alerts by Severity | Severity distribution (1=High, 2=Medium, 3=Low) |
| Top Alert Signatures | `THREAT: Potential Malware Download (.exe)` appears in top signatures |
| Alerts Timeline | Spike in alerts at the time of the download |
| Top Source IPs | Source IP of infected host appears with alert count |
| Protocol Distribution | HTTP traffic proportion visible |

### Incident Timeline Dashboard

Open Grafana → **SOC — Incident Timeline & Drill-Down**

- Alert Timeline shows all 14 alerts over time, color-coded by severity
- Alert Details table shows full event log: timestamp, src_ip, dest_ip, signature, port
- Heatmap clusters events by source IP and time

### Threat Intelligence Dashboard

Open Grafana → **SOC — Threat Intelligence & IOC View**

- DNS queries to suspicious domains (`.cyou`, `.cc`, `.xyz`) show C2 DNS resolution
- HTTP requests to suspicious URIs show the `.exe` download
- Uncommon outbound connections highlight non-standard destination ports

**Evidence:** `grafana/dashboards/` — 3 provisioned dashboard JSONs  
**Screenshots:** `evidence/alerts-overview.png`, `evidence/incident-timeline.png`, `evidence/threat-intel.png`

---

## 3. IOC Extraction — Python Tool

Extract all IOCs from the last 24 hours from the processed eve.json:

```bash
python tools/ioc-extractor.py --last-h 24
```

**Output:**

```
=== IOCs from last 24h (severity <= 3) ===
Total alerts: 14

--- dest_ip (8) ---
  103.232.55.148  (THREAT: Potential Malware Download (.exe))
  104.16.18.94    (THREAT: Nmap Stealth Scan Detected)
  13.107.5.80     (THREAT: Potential Malware Download (.exe))
  ...

--- src_ip (7) ---
  10.0.0.168      (THREAT: Nmap Stealth Scan Detected)
  10.0.0.168      (THREAT: Potential Malware Download (.exe))
  ...

Extracted 15 unique IOCs from 14 alerts
```

**Evidence:** `tools/ioc-extractor.py` — script logic  
Supports `--last-h`, `--min-severity`, `--format csv`, `--eve-path`

---

## 4. Threat Hunting — SQL Queries

Cross-reference the beacon with additional detection queries:

### Suspicious Outbound Traffic

```sql
SELECT src_ip, dest_ip, dest_port, alert_signature, count() AS occurrences
FROM soc.suricata_alerts
WHERE timestamp > now() - INTERVAL 24 HOUR
  AND dest_port NOT IN (80, 443, 8080, 22, 53, 123)
GROUP BY src_ip, dest_ip, dest_port, alert_signature
ORDER BY occurrences DESC;
```

### DNS to Suspicious Domains

```sql
SELECT dns_query AS domain, src_ip AS source, count() AS query_count
FROM soc.suricata_dns
WHERE timestamp > now() - INTERVAL 24 HOUR
  AND (dns_query LIKE '%.cyou' OR dns_query LIKE '%.cc' OR dns_query LIKE '%.xyz')
GROUP BY dns_query, src_ip
ORDER BY query_count DESC;
```

### HTTP Executable Downloads

```sql
SELECT src_ip, url, hostname, http_method, status_code, timestamp
FROM soc.suricata_http
WHERE timestamp > now() - INTERVAL 24 HOUR
  AND (url LIKE '%.exe' OR url LIKE '%.dll' OR url LIKE '%.ps1')
ORDER BY timestamp DESC;
```

**Evidence:** `queries/` — 3 SQL files mapped to MITRE ATT&CK T1046, T1110, T1071, T1105

---

## 5. Automated Response — n8n SOAR Workflows

Three n8n workflows handle different response scenarios:

### Auto-Block IP
- **Trigger:** Webhook receives alert payload
- **Action:** Executes iptables block on source IP
- **Notification:** Posts result to Slack

### Slack Escalation
- **Trigger:** New high-severity alert in ClickHouse
- **Action:** Formats alert data (signature, src_ip, timestamp) into Slack message
- **Output:** Security channel notification with direct link to Grafana

### Ticket Creation
- **Trigger:** Alert severity >= 2
- **Action:** Creates structured incident ticket with all context fields
- **Output:** Ticket ID for tracking through resolution

**Evidence:** `n8n/workflows/` — 3 workflow JSONs (auto-block-ip, slack-escalate, ticket-create)

---

## 6. Incident Response — Playbook

Follow `playbooks/malware-c2-beacon.md` for containment:

1. **Triage** — Verify alert in Grafana, confirm destination IP reputation
2. **Containment** — Block source IP at firewall (auto-block workflow triggers)
3. **IOC Collection** — Extract indicators across network, endpoint, and DNS
4. **Eradication** — Scan infected host, remove malware
5. **Recovery** — Monitor for re-infection, verify beacon traffic stops
6. **Post-Incident** — Document findings, tune rules to reduce future FPs

**Evidence:** `playbooks/malware-c2-beacon.md`, `playbooks/port-scan.md`, `playbooks/ssh-brute-force.md`

---

## 7. Reporting — Executive Summary

Generate a plain-English SOC summary via the report generator:

```bash
pip install clickhouse-driver
python tools/report-generator.py --hours 168 --output report.md
```

**Output:** Markdown report with total alerts, severity breakdown, top signatures, and top source IPs — ready for client distribution.

**Evidence:** `tools/report-generator.py`

---

## Architecture Diagram

```
PCAPs ──→ Suricata (offline -r) ──→ eve.json
                                         │
                                    [Vector] ──→ [ClickHouse] ←── [Grafana]
                                                          │
                                                     [n8n SOAR]
```

## Skills Demonstrated

| SOC Skill | Where |
|---|---|
| Alert triage & severity classification | Grafana dashboards + SQL queries |
| Custom detection rule writing | `suricata/custom.rules` |
| Threat intelligence enrichment | `tools/ioc-extractor.py` + DNS/HTTP threat queries |
| Incident documentation | `playbooks/` + `evidence/detection-logic.md` |
| Automation / SOAR | n8n workflows |
| Log pipeline engineering | Vector → ClickHouse → Grafana |
