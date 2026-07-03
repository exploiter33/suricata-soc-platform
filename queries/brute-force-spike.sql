-- SSH Brute Force Detection Query
-- MITRE: T1110 — Brute Force
-- Returns source IPs with 5+ SSH auth failure alerts in last hour

SELECT
  src_ip,
  count() AS failed_attempts,
  countDistinct(dest_ip) AS targets,
  min(timestamp) AS first_seen,
  max(timestamp) AS last_seen
FROM soc.suricata_alerts
WHERE
  timestamp > now() - INTERVAL 1 HOUR
  AND (
    alert_signature LIKE '%SSH%'
    OR alert_signature LIKE '%brute%'
    OR alert_signature LIKE '%auth%failure%'
  )
GROUP BY src_ip
HAVING failed_attempts >= 5
ORDER BY failed_attempts DESC;
