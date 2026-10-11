# SSH Brute-Force Log Detector

A Python tool that parses a Linux SSH authentication log, counts failed login
attempts per source IP, and flags likely brute-force attackers — including the
dangerous case where an attacker eventually succeeds.

Built as a hands-on cybersecurity lab in log analysis and detection logic.

## What it does

1. **Parses** `auth.log`-style lines with a regex, extracting the source IP
   and username from each failed and successful SSH login.
2. **Counts** failed attempts per IP and **flags** any IP at or above a
   configurable threshold.
3. **Correlates** failures with successes to catch an IP that brute-forced a
   login and then got in — the highest-priority alert.
4. **Reports** the flagged IPs and concrete hardening recommendations.

## Usage

```bash
python3 detect_bruteforce.py --log sample_auth.log
python3 detect_bruteforce.py --log sample_auth.log --threshold 5 --report report.md
```

## Example output

```
[*] Parsed log: 33 failed attempts from 4 distinct IPs.
[*] Flagging IPs with >= 5 failed attempts:

  45.142.120.88     15 failed  (15 usernames)
  185.220.101.47     9 failed  (1 usernames)  <-- SUCCEEDED AFTER FAILURES
  103.76.19.4        7 failed  (5 usernames)
```

The log is crafted to show three real-world patterns:
- `45.142.120.88` sprays 15 common usernames — a classic credential-stuffing
  sweep that never gets in.
- `185.220.101.47` hammers `root` 9 times and then **succeeds** — the tool
  escalates this to a critical alert, because a successful login after many
  failures means the host may be compromised.
- `103.76.19.4` is a moderate scanner.

A legitimate user who fat-fingers their password twice stays **below the
threshold** and is not flagged — showing how the threshold separates noise
from an actual attack.

## How it works

- `parse_log()` runs two regexes over the file: one for `Failed password for
  ... from <ip>` and one for `Accepted password for ... from <ip>`. It builds a
  map of IP to the usernames tried and the usernames that succeeded.
- `analyze()` keeps only IPs at or above the threshold, sorts them by volume,
  and marks any IP that also appears in the successful-login map as breached.
- `build_report()` produces a Markdown summary, with a dedicated "Critical"
  section for any brute-force that ended in a successful login.

## Why this matters (the security lesson)

Internet-facing SSH is scanned constantly. The signal that matters is not a
single failed login but a **pattern**: many failures from one IP, especially
followed by a success. Tuning the threshold is the core trade-off — too low
and you drown in false positives from typos, too high and you miss slow
attacks. This tool makes that trade-off explicit and shows why correlating
failures with successes is what turns raw logs into an actionable alert.

## Files

```
detect_bruteforce.py   # the tool
sample_auth.log        # synthetic auth log with three attack patterns
```

## Responsible use

The sample log is synthetic and the IPs are illustrative. Run this only
against logs you are authorized to analyze.
