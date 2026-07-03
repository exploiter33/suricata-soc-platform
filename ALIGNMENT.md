# Resume Alignment — SOC Analyst / Detection Engineer

Target role alignment mapping resume experience to project deliverables.

| Resume Bullet | Project Evidence | File |
|---|---|---|
| Custom Suricata signatures for SCADA/ICS and IT threats | 7 custom rules: SSH brute force, C2 beacon, ICMP flood, suspicious DNS, malware download | `suricata/custom.rules` |
| Replay packet captures to verify active sensors | Offline `suricata -r` pipeline processing 4 real malware pcaps (Lokibot, MS17-010, Lumma Stealer) | `scripts/replay-attacks.sh` |
| MITRE ATT&CK matrix mapping to find blind spots | All rules and hunting queries mapped to Enterprise techniques (T1046, T1110, T1071, T1568, T1105) | `queries/MITRE-MAPPING.md` |
| Python tools to automate log checks and reduce false positives | IOC extractor from eve.json by time window + severity; report generator querying ClickHouse | `tools/ioc-extractor.py`, `tools/report-generator.py` |
| Log ingestion and parsing pipeline | Vector config parses 747-line eve.json, normalizes timestamps, flattens fields into 3 ClickHouse tables | `suricata/eve2vector.toml` |
| Alert triage and SIEM dashboards | 3 Grafana dashboards (11 panels): severity breakdown, timeline, source IP clustering, threat intel | `grafana/dashboards/` |
| Technical runbook creation | 3 NIST 800-61 style IR playbooks: port scan, SSH brute force, malware C2 beacon | `playbooks/` |
| End-to-end incident handling (ticket → fix → closure) | n8n SOAR workflows: auto-block IP, Slack escalation, ticket creation via webhook | `n8n/workflows/` |
| Traffic analysis with Wireshark and PCAP investigation | 4 pcaps replayed offline; HTTP, DNS, and alert data extracted into structured tables | `pcaps/` |
| Docker and Linux infrastructure | 5-container stack: ClickHouse, Vector, Grafana, n8n, PostgreSQL | `docker-compose.yml` |
| Bash scripting for operational tasks | Replay all pcaps single-command; simulate-attacks for live Suricata validation | `scripts/` |
