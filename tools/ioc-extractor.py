#!/usr/bin/env python3
"""
IOC Extractor — pull Indicators of Compromise from Suricata eve.json.

Usage:
  python ioc-extractor.py --last-h 24
  python ioc-extractor.py --last-h 48 --min-severity 2
  python ioc-extractor.py --format csv
"""

import json
import argparse
import time
import os
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
EVE_PATH = SCRIPT_DIR / "suricata" / "eve.json"


def parse_args():
    parser = argparse.ArgumentParser(description="Extract IOCs from Suricata eve.json")
    parser.add_argument("--last-h", type=int, default=24, help="Hours to look back")
    parser.add_argument("--min-severity", type=int, default=3, help="Max inclusive severity (1=high, 3=low; default 3 includes all)")
    parser.add_argument("--format", choices=["txt", "csv"], default="txt")
    parser.add_argument("--eve-path", default=None, help="Path to eve.json (default: ./suricata/eve.json)")
    return parser.parse_args()


def is_in_window(ts, hours):
    try:
        event_time = time.mktime(time.strptime(ts.split(".")[0], "%Y-%m-%dT%H:%M:%S"))
        return (time.time() - event_time) < (hours * 3600)
    except (ValueError, AttributeError):
        return False


def extract():
    args = parse_args()
    iocs = defaultdict(set)
    eve = Path(args.eve_path) if args.eve_path else EVE_PATH

    if not eve.exists():
        print(f"eve.json not found at {EVE_PATH}")
        return

    count = 0
    with eve.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("event_type") != "alert":
                continue
            if not is_in_window(ev.get("timestamp", ""), args.last_h):
                continue
            if ev.get("alert", {}).get("severity", 3) > args.min_severity:
                continue

            src_ip = ev.get("src_ip")
            dest_ip = ev.get("dest_ip")
            signature = ev.get("alert", {}).get("signature", "unknown")

            if src_ip and src_ip not in ("0.0.0.0", "::"):
                iocs["src_ip"].add((src_ip, signature))
            if dest_ip and dest_ip not in ("0.0.0.0", "::"):
                iocs["dest_ip"].add((dest_ip, signature))
            count += 1

    if not iocs:
        print(f"No IOCs found in the last {args.last_h}h (min severity {args.min_severity})")
        return

    if args.format == "csv":
        print("type,value,signature")
        for ioc_type, values in iocs.items():
            for val, sig in values:
                print(f"{ioc_type},{val},{sig}")
    else:
        print(f"=== IOCs from last {args.last_h}h (severity ≤ {args.min_severity}) ===")
        print(f"Total alerts: {count}\n")
        for ioc_type, values in sorted(iocs.items()):
            print(f"--- {ioc_type} ({len(values)}) ---")
            for val, sig in sorted(values):
                print(f"  {val}  ({sig})")

    print(f"\nExtracted {sum(len(v) for v in iocs.values())} unique IOCs from {count} alerts")


if __name__ == "__main__":
    extract()
