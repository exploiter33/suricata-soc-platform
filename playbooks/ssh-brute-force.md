# IR Playbook: SSH Brute Force Attack

## Objective
Detect and stop SSH credential stuffing / brute force attacks.

## Detection Sources
- Custom rule `sid:1000001` — excessive SSH auth failures same source
- Dashboard: single `src_ip` with 10+ SSH-related alerts in short window
- Auth log correlation (if available)

## Triage Steps

### 1. Confirm the Attack
```bash
# Query ClickHouse
SELECT src_ip, count() AS attempts, max(timestamp) AS last
FROM soc.suricata_alerts
WHERE alert_signature LIKE '%SSH%brute%' AND timestamp > now() - INTERVAL 1 HOUR
GROUP BY src_ip HAVING attempts > 5;
```

### 2. Check if Already Compromised
```bash
grep "Accepted" /var/log/auth.log | grep <attacker_ip>
```
If any successful logins from attacker IP → assume compromise.

### 3. Contain
```bash
# Block attacker IP
sudo iptables -A INPUT -s <attacker_ip> -j DROP

# If SSH on non-standard port, verify it's still necessary
# If password auth enabled, disable in /etc/ssh/sshd_config:
# PasswordAuthentication no
# Restart SSH: sudo systemctl restart sshd
```

### 4. Post-Incident Actions
- Rotate any exposed credentials
- Check for unauthorized key additions in `~/.ssh/authorized_keys`
- Enable `fail2ban` for SSH if not already active
- Consider moving SSH to key-only authentication

## Prevention
- Disable password-based SSH auth
- Use SSH keys only
- Run SSH on non-standard port (optional, security-through-obscurity is weak)
- Deploy fail2ban

## MITRE ATT&CK Mapping
- **T1110** — Brute Force
- **T1110.001** — Password Guessing
- **T1110.002** — Password Cracking
- **T1110.003** — Password Spraying
