-- Port Scan Detection Query
-- MITRE: T1046 — Network Service Scanning
-- Returns source IPs that hit 10+ unique destinations or ports in last hour

SELECT
  src_ip,
  count() AS total_connections,
  countDistinct(dest_ip) AS unique_destinations,
  countDistinct(dest_port) AS unique_ports,
  max(timestamp) AS last_seen
FROM soc.suricata_alerts
WHERE
  timestamp > now() - INTERVAL 1 HOUR
  AND (
    alert_signature LIKE '%SCAN%'
    OR alert_signature LIKE '%Nmap%'
    OR alert_signature LIKE '%portscan%'
  )
GROUP BY src_ip
HAVING total_connections > 5
ORDER BY total_connections DESC;
