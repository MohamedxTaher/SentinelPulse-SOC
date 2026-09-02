"""Sliding-window brute force detector for SentinelPulse SOC Analytics.

Counts failed authentication attempts per source IP inside a moving time
window rather than over the whole file. Nine attempts in 30 seconds and
nine attempts across three days are very different signals — attack rate
matters more than total volume, and this detector preserves that
distinction.

Usage:
    python soc/brute_force_detector/detector.py \
        --file sample.log --threshold 5 --window 300

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

LOG_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
    r"(?:Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)"
)
TIME_FORMAT = "%b %d %H:%M:%S"


def parse_attempts(filepath):
    """Extract (timestamp, ip) pairs for every failed auth attempt."""
    attempts = defaultdict(list)
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = LOG_PATTERN.search(line)
                if not match:
                    continue
                timestamp_str, ip = match.groups()
                try:
                    timestamp = datetime.strptime(
                        timestamp_str.strip(), TIME_FORMAT
                    ).replace(year=datetime.now().year)
                except ValueError:
                    # Unparseable clock data should never hide an attempt.
                    timestamp = datetime.now()
                attempts[ip].append(timestamp)
    except OSError as exc:
        print(f"error: cannot read {filepath}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return attempts


def detect(attempts, threshold, window_seconds):
    """Flag IPs whose densest sliding window meets the threshold.

    Uses a two-pointer sweep over each IP's sorted timestamps, so large
    auth logs stay linear instead of degrading quadratically.
    """
    flagged = {}
    window = timedelta(seconds=window_seconds)

    for ip, timestamps in attempts.items():
        if len(timestamps) < threshold:
            continue

        timestamps_sorted = sorted(timestamps)
        max_in_window = 0
        left = 0
        for right, moment in enumerate(timestamps_sorted):
            while moment - timestamps_sorted[left] > window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window >= threshold:
            flagged[ip] = {
                "count": len(timestamps),
                "max_in_window": max_in_window,
            }
    return flagged


def print_report(flagged, threshold, window):
    """Print the detection report with block/monitor recommendations."""
    print("\nBrute Force Detection Report")
    print("=" * 60)
    print(f"Threshold : {threshold} attempts within {window} seconds\n")

    if not flagged:
        print("No brute force activity detected.")
        return

    print("FLAGGED IPs:")
    ranked = sorted(
        flagged.items(),
        key=lambda item: item[1]["max_in_window"],
        reverse=True,
    )
    for ip, data in ranked:
        if data["max_in_window"] >= threshold * 2:
            status = "BLOCK RECOMMENDED"
        else:
            status = "MONITOR"
        print(
            f"  {ip:<20} {data['max_in_window']} in window / "
            f"{data['count']} total   {status}"
        )


def main():
    """CLI entry point for the brute force detector."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-detector",
        description="Detect brute force attempts from auth logs",
    )
    cli.add_argument("--file", required=True, help="Path to auth log file")
    cli.add_argument(
        "--threshold", type=int, default=5,
        help="Failed attempts required inside the window",
    )
    cli.add_argument(
        "--window", type=int, default=300,
        help="Sliding time window in seconds",
    )
    args = cli.parse_args()

    attempts = parse_attempts(args.file)
    flagged = detect(attempts, args.threshold, args.window)
    print_report(flagged, args.threshold, args.window)


if __name__ == "__main__":
    main()
