#!/usr/bin/env python3
"""
Suricata Rule Manager — enable, disable, and test custom rules.

NOTE: This tool works with live Suricata (sudo systemctl). For offline pcap
replay, use scripts/replay-attacks.sh instead.

Usage:
  python suricata-rule-manager.py list
  python suricata-rule-manager.py enable <sid>
  python suricata-rule-manager.py disable <sid>
  python suricata-rule-manager.py test <sid> [--eve-path <path>]
  python suricata-rule-manager.py stats
"""

import subprocess
import sys
import re

RULES_FILE = "/etc/suricata/rules/custom.rules"
EVE_REPLAY_PATH = None


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def load_rules():
    try:
        with open(RULES_FILE) as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"Rules file not found at {RULES_FILE}")
        sys.exit(1)


def save_rules(lines):
    with open(RULES_FILE, "w") as f:
        f.writelines(lines)


def list_rules():
    lines = load_rules()
    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        sid_match = re.search(r"sid:(\d+);", line)
        msg_match = re.search(r'msg:"([^"]+)"', line)
        sid = sid_match.group(1) if sid_match else "?"
        msg = msg_match.group(1) if msg_match else "?"
        status = "DISABLED" if line.startswith("# ") else "ENABLED "
        print(f"  [{status}] sid:{sid} — {msg}")


def toggle_rule(sid, disable=False):
    lines = load_rules()
    found = False
    for i, line in enumerate(lines):
        if f"sid:{sid};" in line:
            found = True
            if disable:
                if not line.strip().startswith("#"):
                    lines[i] = f"# {line}"
                    print(f"Disabled rule sid:{sid}")
            else:
                lines[i] = re.sub(r"^#\s*", "", line)
                print(f"Enabled rule sid:{sid}")
            break
    if not found:
        print(f"Rule sid:{sid} not found")
        return
    save_rules(lines)
    print("Restarting Suricata...")
    run("sudo systemctl restart suricata")
    print("Done.")


def test_rule(sid):
    path = EVE_REPLAY_PATH if EVE_REPLAY_PATH else "/var/log/suricata/eve.json"
    print(f"Searching for sid:{sid} in {path}...")
    result = run(f"grep '\"sid\":{sid}' {path} | tail -5")
    if result.stdout:
        print(result.stdout[:2000])
    else:
        print(f"No recent matches for sid:{sid} in {path}")


def stats():
    result = run("suricata --dump-rules 2>/dev/null || echo 'not available'")
    print("=== Suricata Stats ===")
    result2 = run("suricatasc -c 'dump-counters' 2>/dev/null | tail -30")
    if result2.stdout:
        print(result2.stdout)
    else:
        print("Run 'suricatasc -c dump-counters' for live stats")


if __name__ == "__main__":
    global EVE_REPLAY_PATH
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = [a for a in sys.argv[1:] if a.startswith("--")]

    for opt in opts:
        if opt.startswith("--eve-path="):
            EVE_REPLAY_PATH = opt.split("=", 1)[1]

    if len(args) < 1:
        print(__doc__)
        sys.exit(1)

    cmd = args[0]
    if cmd == "list":
        list_rules()
    elif cmd == "enable" and len(args) >= 2:
        toggle_rule(args[1], disable=False)
    elif cmd == "disable" and len(args) >= 2:
        toggle_rule(args[1], disable=True)
    elif cmd == "test" and len(args) >= 2:
        test_rule(args[1])
    elif cmd == "stats":
        stats()
    else:
        print(__doc__)
