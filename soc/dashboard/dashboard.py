"""Terminal dashboard for SentinelPulse SOC Analytics.

A single-screen operational view over parsed log data: volume by log
type, top source IPs, HTTP status distribution and the most recent
suspicious events. Designed for a quick pulse-check between alert
triage cycles.

Usage:
    python soc/dashboard/dashboard.py --logs parsed.json

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import json
import sys
from collections import Counter


def load_logs(filepath):
    """Load parsed log entries from a JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            logs = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {filepath}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(logs, list):
        print(f"error: {filepath} does not contain a log array", file=sys.stderr)
        raise SystemExit(1)
    return logs


def bar(value, max_value, width=25):
    """Render a proportional unicode bar for terminal histograms."""
    if not max_value:
        return "░" * width
    filled = int((value / max_value) * width)
    return "█" * filled + "░" * (width - filled)


def print_dashboard(entries):
    """Print the full dashboard view."""
    total = len(entries)
    suspicious = [entry for entry in entries if entry.get("suspicious")]
    types = Counter(entry.get("type", "unknown") for entry in entries)
    ips = Counter(
        entry.get("ip") for entry in entries if entry.get("ip")
    ).most_common(5)
    codes = Counter(
        entry.get("status") for entry in entries if entry.get("status")
    ).most_common(5)

    print("=" * 55)
    print("        SENTINELPULSE SOC — LIVE OVERVIEW")
    print("=" * 55)
    print(f"\n  Total log entries  : {total}")
    print(f"  Suspicious events  : {len(suspicious)}")

    print("\n  Log types:")
    max_type = max(types.values(), default=1)
    for log_type, count in types.items():
        print(f"    {log_type:<12} {bar(count, max_type)} {count}")

    if ips:
        print("\n  Top source IPs:")
        max_ip = max(count for _, count in ips)
        for ip, count in ips:
            print(f"    {ip:<18} {bar(count, max_ip, 15)} {count}")

    if codes:
        print("\n  HTTP status codes:")
        max_code = max(count for _, count in codes)
        for code, count in codes:
            print(f"    {code:<6} {bar(count, max_code, 15)} {count}")

    if suspicious:
        print("\n  Recent suspicious events:")
        for entry in suspicious[-5:]:
            message = (
                entry.get("message")
                or entry.get("request")
                or entry.get("raw", "")
            )
            print(f"    [{entry.get('type')}] {message[:55]}")

    print("\n" + "=" * 55)


def main():
    """CLI entry point for the terminal dashboard."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-dashboard",
        description="Terminal dashboard for parsed log data",
    )
    cli.add_argument("--logs", required=True, help="Parsed JSON log file")
    args = cli.parse_args()

    entries = load_logs(args.logs)
    print_dashboard(entries)


if __name__ == "__main__":
    main()
