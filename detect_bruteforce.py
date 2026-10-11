#!/usr/bin/env python3
"""
detect_bruteforce.py — SSH Brute-Force Log Detector

Parses a Linux SSH auth log (e.g. /var/log/auth.log), counts failed login
attempts per source IP, and flags any IP that crosses a threshold as a likely
brute-force attacker. Produces a human-readable report.

Educational project. Run it against your own logs or the sample provided.

Usage:
    python3 detect_bruteforce.py --log sample_auth.log
    python3 detect_bruteforce.py --log sample_auth.log --threshold 5 --report report.md
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# A failed SSH password attempt in auth.log looks like:
#   Failed password for invalid user admin from 192.168.1.50 port 52344 ssh2
#   Failed password for root from 10.0.0.5 port 41920 ssh2
# This regex captures the (optional) username and the source IP.
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# A successful login (to spot an attacker who eventually got in):
#   Accepted password for deploy from 203.0.113.9 port 50122 ssh2
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_log(path):
    """
    Read the log and return:
      failed_by_ip:   {ip: [usernames tried]}
      accepted_by_ip: {ip: [usernames that succeeded]}
    """
    failed_by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = FAILED_RE.search(line)
                if m:
                    failed_by_ip[m.group("ip")].append(m.group("user"))
                    continue
                a = ACCEPTED_RE.search(line)
                if a:
                    accepted_by_ip[a.group("ip")].append(a.group("user"))
    except FileNotFoundError:
        sys.exit(f"[!] Log file not found: {path}")
    return failed_by_ip, accepted_by_ip


def analyze(failed_by_ip, accepted_by_ip, threshold):
    """Return a sorted list of attacker records for IPs over the threshold."""
    attackers = []
    for ip, users in failed_by_ip.items():
        if len(users) >= threshold:
            attackers.append({
                "ip": ip,
                "failed_attempts": len(users),
                "unique_users": sorted(set(users)),
                "breached": ip in accepted_by_ip,
                "breached_users": sorted(set(accepted_by_ip.get(ip, []))),
            })
    # Most aggressive attackers first.
    attackers.sort(key=lambda a: a["failed_attempts"], reverse=True)
    return attackers


def build_report(attackers, total_failed, threshold):
    """Assemble a Markdown report from the attacker records."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append("# SSH Brute-Force Detection Report")
    lines.append("")
    lines.append(f"- Generated: {now}")
    lines.append(f"- Total failed login attempts: {total_failed}")
    lines.append(f"- Alert threshold: {threshold} failed attempts per IP")
    lines.append(f"- Suspicious IPs flagged: {len(attackers)}")
    lines.append("")

    if not attackers:
        lines.append("No IP crossed the threshold. Nothing to flag.")
        return "\n".join(lines)

    lines.append("## Flagged source IPs")
    lines.append("")
    lines.append("| Source IP | Failed attempts | Distinct usernames | Succeeded? |")
    lines.append("| --- | --- | --- | --- |")
    for a in attackers:
        flag = "**YES — investigate now**" if a["breached"] else "no"
        lines.append(f"| `{a['ip']}` | {a['failed_attempts']} | "
                     f"{len(a['unique_users'])} | {flag} |")
    lines.append("")

    # Call out any IP that both brute-forced AND eventually logged in.
    breached = [a for a in attackers if a["breached"]]
    if breached:
        lines.append("## Critical: brute-force followed by a successful login")
        lines.append("")
        for a in breached:
            users = ", ".join(a["breached_users"])
            lines.append(f"- `{a['ip']}` failed {a['failed_attempts']} times, then "
                         f"logged in successfully as **{users}**. Treat this host as "
                         "potentially compromised.")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("- **Block the flagged IPs** at the firewall and deploy "
                 "fail2ban (or similar) to ban IPs automatically after a few failures.")
    lines.append("- **Disable password authentication** and use SSH keys; "
                 "set `PasswordAuthentication no` in `sshd_config`.")
    lines.append("- **Disable direct root login** (`PermitRootLogin no`).")
    lines.append("- **Rate-limit / move the SSH port** and restrict access to known "
                 "source ranges where possible.")
    lines.append("- For any IP that succeeded after many failures, **rotate that "
                 "account's credentials and audit the host** for signs of compromise.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by detect_bruteforce.py. For authorized use only.*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts in an auth log.")
    parser.add_argument("--log", required=True,
                        help="Path to the SSH auth log.")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts from one IP before it's flagged "
                             "(default: 5).")
    parser.add_argument("--report", default=None,
                        help="Optional path to write a Markdown report.")
    args = parser.parse_args()

    failed_by_ip, accepted_by_ip = parse_log(args.log)
    total_failed = sum(len(v) for v in failed_by_ip.values())
    attackers = analyze(failed_by_ip, accepted_by_ip, args.threshold)

    print(f"[*] Parsed log: {total_failed} failed attempts "
          f"from {len(failed_by_ip)} distinct IPs.")
    print(f"[*] Flagging IPs with >= {args.threshold} failed attempts:\n")

    if not attackers:
        print("  (none crossed the threshold)")
    for a in attackers:
        tag = "  <-- SUCCEEDED AFTER FAILURES" if a["breached"] else ""
        print(f"  {a['ip']:<16} {a['failed_attempts']:>3} failed  "
              f"({len(a['unique_users'])} usernames){tag}")

    report = build_report(attackers, total_failed, args.threshold)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"\n[*] Report written to {args.report}")


if __name__ == "__main__":
    main()
