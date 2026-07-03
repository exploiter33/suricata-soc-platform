# MITRE ATT&CK Mapping

Every detection in this SOC platform maps to one or more MITRE ATT&CK techniques.

| Technique ID | Name | Detection Source | Query / Rule |
|---|---|---|---|
| **T1046** | Network Service Scanning | Suricata ET SCAN rules, Custom rule sid:1000003 (ICMP) | `queries/port-scan-detection.sql` |
| **T1595** | Active Scanning | Suricata ET SCAN rules | `queries/port-scan-detection.sql` |
| **T1110** | Brute Force | Custom rule sid:1000001 (SSH threshold) | `queries/brute-force-spike.sql` |
| **T1110.001** | Password Guessing | Custom rule sid:1000001 | `queries/brute-force-spike.sql` |
| **T1110.002** | Password Cracking | Excessive auth failures | `queries/brute-force-spike.sql` |
| **T1071.001** | Web Protocols (C2) | Custom rule sid:1000002 (non-standard port outbound) | `queries/suspicious-traffic.sql` |
| **T1071.004** | DNS (C2) | Custom rules sid:1000004-6 (suspicious TLDs) | `queries/suspicious-traffic.sql` |
| **T1105** | Ingress Tool Transfer | Custom rule sid:1000007 (.exe download) | `queries/suspicious-traffic.sql` |
| **T1568** | Dynamic Resolution | DNS to DGA-like domains | `queries/suspicious-traffic.sql` |
| **T1572** | Protocol Tunneling | Outbound on uncommon ports | `queries/suspicious-traffic.sql` |

## Coverage by Tactic

| Tactic | Techniques Covered |
|---|---|
| Reconnaissance | T1046, T1595 |
| Credential Access | T1110, T1110.001, T1110.002 |
| Command & Control | T1071.001, T1071.004, T1568 |
| Defense Evasion | T1572 |
| Execution | (monitored via .exe/.ps1 downloads — T1105) |
