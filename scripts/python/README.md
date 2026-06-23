# Python Security Scripts

Security analysis tools written in Python. Built as part of MSCSIA coursework and independent study — each script is functional, not just academic.

---

## log_analyzer.py — SSH Auth Log Threat Analyzer

Parses Linux SSH authentication logs (`auth.log`) to surface brute force attempts, credential stuffing, and unauthorized access patterns. No external libraries required — runs on any machine with Python 3.

### Usage

```bash
python log_analyzer.py <logfile>
python log_analyzer.py <logfile> --threshold 20
python log_analyzer.py <logfile> --output report.txt
```

**Test it with the included sample log:**

```bash
python log_analyzer.py sample_logs/auth.log
```

### What the report shows

| Section | What it means |
|---|---|
| Threat Flags | IPs that exceeded the brute force threshold |
| Top Attacking IPs | All IPs with failures, sorted by attempt count |
| Most Targeted Usernames | Common credential stuffing targets (root, admin, etc.) |
| Successful Logins | Legitimate access — cross-reference against attacking IPs |

### Options

| Flag | Default | Description |
|---|---|---|
| `--threshold` | 10 | Failed attempts before an IP is flagged as brute force |
| `--output` | none | Save report to a text file in addition to printing |

---

## Analyst Workflow — What to Do With the Output

Running this script is step one. Here is what an analyst does next:

**1. Geolocate flagged IPs**
Look up each brute force IP in a threat intelligence tool such as AbuseIPDB or run `whois`. Identify where the IP is registered and whether other organizations have already reported it as malicious. A known threat actor IP is an immediate escalation.

**2. Check whether anything succeeded**
The report separates failed logins from successful ones. If a successful login appears from the same IP that was brute forcing, that is an active incident — someone got in. Every other step stops and incident response begins.

**3. Cross-reference the timestamp**
Note when the attack occurred and look at other logs covering the same window: file access logs, database logs, web server logs. Attackers do not log in and sit still. Correlating across log sources is how you build a full picture of what happened.

**4. Block or escalate**
Depending on your role, this means writing a firewall rule to block the IP, adding it to a SIEM watchlist, or documenting findings for the team that owns incident response. In a consulting engagement, this goes into a findings report with a recommended remediation.

**5. Document the misconfiguration**
A server receiving 50 attempts targeting `root` via SSH likely has root login enabled — that is a configuration finding, not just an attack. Document it, recommend disabling direct root SSH access (`PermitRootLogin no` in sshd_config), and include it in the remediation report. The attack is the symptom. The misconfiguration is the vulnerability.

---

## How It Works

The script uses Python's `re` module to apply regex patterns against each log line. Three pieces of data are extracted from every matched line: timestamp, username, and source IP. Those are tallied across the entire file and then formatted into the report. No third-party libraries. Runs offline.

For a line-by-line walkthrough of the code, see the comments inside `log_analyzer.py`.
