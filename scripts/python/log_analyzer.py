#!/usr/bin/env python3
"""
log_analyzer.py — SSH Authentication Log Threat Analyzer

Parses Linux auth.log to surface brute force attempts,
credential stuffing, and unauthorized access patterns.

Usage:
    python log_analyzer.py <logfile>
    python log_analyzer.py <logfile> --threshold 20
    python log_analyzer.py <logfile> --output report.txt
    python log_analyzer.py sample_logs/auth.log
"""

import sys
import re
import argparse
from collections import defaultdict
from datetime import datetime


FAILED_RE = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+).*sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from ([\d.]+)'
)
ACCEPTED_RE = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+).*sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from ([\d.]+)'
)


def parse_args():
    p = argparse.ArgumentParser(
        description='SSH Auth Log Threat Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python log_analyzer.py /var/log/auth.log --threshold 20 -o report.txt'
    )
    p.add_argument('logfile', help='Path to auth.log or similar authentication log')
    p.add_argument('--threshold', type=int, default=10,
                   help='Failed attempts to flag as brute force (default: 10)')
    p.add_argument('--output', '-o', metavar='FILE',
                   help='Write report to file in addition to stdout')
    return p.parse_args()


def analyze(logfile, threshold):
    by_ip   = defaultdict(lambda: {'count': 0, 'users': set(), 'first': None, 'last': None})
    by_user = defaultdict(int)
    accepted = []
    timestamps = []
    total = 0

    try:
        with open(logfile, 'r', errors='replace') as f:
            for line in f:
                total += 1

                m = FAILED_RE.search(line)
                if m:
                    ts, user, ip = m.groups()
                    rec = by_ip[ip]
                    rec['count'] += 1
                    rec['users'].add(user)
                    if rec['first'] is None:
                        rec['first'] = ts
                    rec['last'] = ts
                    by_user[user] += 1
                    timestamps.append(ts)
                    continue

                m = ACCEPTED_RE.search(line)
                if m:
                    ts, user, ip = m.groups()
                    accepted.append({'time': ts, 'user': user, 'ip': ip})
                    timestamps.append(ts)

    except FileNotFoundError:
        print(f'[ERROR] File not found: {logfile}')
        sys.exit(1)
    except PermissionError:
        print(f'[ERROR] Permission denied: {logfile}')
        sys.exit(1)

    return {
        'total_lines' : total,
        'total_failed': sum(d['count'] for d in by_ip.values()),
        'by_ip'       : by_ip,
        'by_user'     : by_user,
        'accepted'    : accepted,
        'brute_force' : {ip: d for ip, d in by_ip.items() if d['count'] >= threshold},
        'time_range'  : (timestamps[0], timestamps[-1]) if timestamps else ('N/A', 'N/A'),
        'threshold'   : threshold,
    }


def build_report(r, logfile):
    W    = 64
    SEP  = '=' * W
    THIN = '-' * W
    now  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    out = []
    def ln(s=''): out.append(s)

    ln(SEP)
    ln('  SSH AUTH LOG - THREAT ANALYSIS REPORT')
    ln(f'  Generated : {now}')
    ln(f'  Source    : {logfile}')
    ln(SEP)
    ln()

    ln('SUMMARY')
    ln(THIN)
    ln(f'  Log lines analyzed    : {r["total_lines"]:,}')
    ln(f'  Time range            : {r["time_range"][0]}  ->  {r["time_range"][1]}')
    ln(f'  Failed login attempts : {r["total_failed"]:,}')
    ln(f'  Successful logins     : {len(r["accepted"]):,}')
    ln(f'  Unique attacking IPs  : {len(r["by_ip"]):,}')
    ln(f'  Brute force threshold : >= {r["threshold"]} attempts')
    ln()

    ln('THREAT FLAGS')
    ln(THIN)
    if r['brute_force']:
        for ip, d in sorted(r['brute_force'].items(), key=lambda x: -x[1]['count']):
            ln(f'  [!] BRUTE FORCE   {ip:<18}  {d["count"]:>5} attempts')
    else:
        ln('  None detected above threshold.')
    ln()

    ln('TOP ATTACKING IPs')
    ln(THIN)
    top_ips = sorted(r['by_ip'].items(), key=lambda x: -x[1]['count'])[:15]
    if top_ips:
        ln(f'  {"IP Address":<18}  {"Attempts":>8}   Usernames Tried')
        ln(f'  {"-"*18}  {"-"*8}   {"-"*24}')
        for ip, d in top_ips:
            users = sorted(d['users'])
            shown = ', '.join(users[:4])
            if len(users) > 4:
                shown += f' (+{len(users) - 4} more)'
            ln(f'  {ip:<18}  {d["count"]:>8}   {shown}')
    else:
        ln('  No failed logins found.')
    ln()

    ln('MOST TARGETED USERNAMES')
    ln(THIN)
    top_users = sorted(r['by_user'].items(), key=lambda x: -x[1])[:10]
    if top_users:
        ln(f'  {"Username":<20}  {"Attempts":>8}')
        ln(f'  {"-"*20}  {"-"*8}')
        for user, count in top_users:
            ln(f'  {user:<20}  {count:>8}')
    else:
        ln('  No failed logins found.')
    ln()

    ln('SUCCESSFUL LOGINS')
    ln(THIN)
    if r['accepted']:
        for e in r['accepted']:
            ln(f'  {e["time"]}   {e["user"]:<15}  from {e["ip"]}')
    else:
        ln('  None found in log.')
    ln()

    ln(SEP)
    ln(f'  End of report - {len(r["brute_force"])} brute force source(s) flagged')
    ln(SEP)

    return '\n'.join(out)


def main():
    args    = parse_args()
    results = analyze(args.logfile, args.threshold)
    report  = build_report(results, args.logfile)

    print(report)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f'\nReport saved to {args.output}')


if __name__ == '__main__':
    main()
