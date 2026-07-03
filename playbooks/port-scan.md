# IR Playbook: Port Scan Detection

## Objective
Investigate and respond to a detected port scan against internal or DMZ assets.

## Detection Sources
- Suricata signature: `ET SCAN Nmap` / `ET SCAN SYN`
- SOC dashboard: spike in `alert_severity=3` alerts from single source IP
- Custom rule `sid:1000001` (SSH brute) — often preceded by port scan

## Triage Steps

### 1. Verify the Alert
```
Query ClickHouse:
SELECT src_ip, count() AS cnt, countDistinct(dest_port) AS ports_scanned
FROM soc.suricata_alerts
WHERE alert_signature LIKE '%SCAN%' AND timestamp > now() - INTERVAL 1 HOUR
GROUP BY src_ip ORDER BY cnt DESC;
```

### 2. Check Blocklists
- Search `src_ip` against VirusTotal / AlienVault OTX
- Check internal threat intel feeds
- Check if IP appears in recent scans across other assets

### 3. Determine Intent
| Signal | Likely Intent |
|--------|---------------|
| Scan across many ports | Reconnaissance |
| Scan only 1-2 ports | Targeted check |
| Scan from known scanner IP | Research / authorized testing |
| Scan from unknown foreign IP | Pre-attack recon |

### 4. Contain
```bash
# If clearly malicious, block at firewall:
iptables -A INPUT -s <attacker_ip> -j DROP
# For n8n users: trigger auto-block-ip workflow
```

### 5. Escalation Criteria
- Escalate to Tier 2 if combined with any exploit attempt (alert_severity=1 or 2 within 1h)
- Escalate if scan targets critical infrastructure (AD, database, payment)

## Remediation
- Ensure no public-facing services on unexpected ports
- Verify firewall rules restrict inbound to necessary ports only
- Add source IP to blocklist for 24h minimum

## MITRE ATT&CK Mapping
- **T1046** — Network Service Scanning
- **T1595** — Active Scanning
