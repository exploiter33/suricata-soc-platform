CREATE DATABASE IF NOT EXISTS soc;

CREATE TABLE IF NOT EXISTS soc.suricata_alerts (
    timestamp DateTime,
    src_ip String,
    src_port UInt16,
    dest_ip String,
    dest_port UInt16,
    proto String,
    alert_sid UInt32,
    alert_gid UInt32,
    alert_rev UInt32,
    alert_severity UInt8,
    alert_signature String,
    alert_category String,
    flow_id UInt64,
    event_type String
) ENGINE = MergeTree()
ORDER BY timestamp;

CREATE TABLE IF NOT EXISTS soc.suricata_http (
    timestamp DateTime,
    src_ip String,
    dest_ip String,
    hostname String,
    url String,
    http_method String,
    status_code UInt16,
    user_agent String,
    content_type String,
    event_type String
) ENGINE = MergeTree()
ORDER BY timestamp;

CREATE TABLE IF NOT EXISTS soc.suricata_dns (
    timestamp DateTime,
    src_ip String,
    dest_ip String,
    dns_query String,
    dns_type String,
    dns_rcode String,
    dns_answers Array(String),
    event_type String
) ENGINE = MergeTree()
ORDER BY timestamp;
