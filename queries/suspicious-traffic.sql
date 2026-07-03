-- Suspicious Outbound Traffic Detection
-- MITRE: T1071.001 — Web Protocols / T1071.004 — DNS
-- Finds hosts making unusual outbound connections (non-standard ports, suspicious TLDs)

-- 1. Outbound to uncommon ports
SELECT
  src_ip,
  dest_ip,
  dest_port,
  alert_signature,
  count() AS occurrences,
  max(timestamp) AS last_seen
FROM soc.suricata_alerts
WHERE
  timestamp > now() - INTERVAL 24 HOUR
  AND dest_ip NOT LIKE '10.%'
  AND dest_ip NOT LIKE '192.168.%'
  AND dest_ip NOT LIKE '172.16.%'
  AND dest_port NOT IN (80, 443, 8080, 22, 53, 123)
GROUP BY src_ip, dest_ip, dest_port, alert_signature
ORDER BY occurrences DESC;

-- 2. DNS queries to suspicious TLDs
SELECT
  dns_query AS domain,
  src_ip AS source,
  count() AS query_count
FROM soc.suricata_dns
WHERE
  timestamp > now() - INTERVAL 24 HOUR
  AND (
    dns_query LIKE '%.xyz'
    OR dns_query LIKE '%.top'
    OR dns_query LIKE '%.tk'
    OR dns_query LIKE '%.ml'
    OR dns_query LIKE '%.gq'
    OR dns_query LIKE '%.cf'
  )
GROUP BY dns_query, src_ip
ORDER BY query_count DESC;

-- 3. HTTP downloads of executables
SELECT
  src_ip,
  url,
  hostname,
  http_method,
  status_code,
  timestamp
FROM soc.suricata_http
WHERE
  timestamp > now() - INTERVAL 24 HOUR
  AND (
    url LIKE '%.exe'
    OR url LIKE '%.dll'
    OR url LIKE '%.ps1'
    OR url LIKE '%.vbs'
    OR url LIKE '%.bat'
    OR url LIKE '%.jar'
  )
ORDER BY timestamp DESC;
