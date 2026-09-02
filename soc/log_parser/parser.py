"""Raw log ingestion for SentinelPulse SOC Analytics.

Reads log files line by line, classifies each entry as syslog, Apache
combined access, or SSH/PAM authentication, and flags lines that carry
suspicious keywords. Output is structured JSON that the alert engine and
the brute force detector can consume directly.

Usage:
    python soc/log_parser/parser.py --file sample.log --output parsed.json

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import json
import re
import sys

# Ordered by specificity: auth lines are matched before generic syslog so
# sshd/sudo events keep their dedicated service field instead of being
# lumped in with everything else the host emits.
PATTERNS = {
    "auth": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<service>sshd|sudo|login)(?:\[\d+\])?:\s+"
        r"(?P<message>.+)"
    ),
    "apache": re.compile(
        r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)")?'
        r'(?:\s+"(?P<user_agent>[^"]*)")?'
    ),
    "syslog": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)"
    ),
}

SUSPICIOUS_KEYWORDS = [
    "failed password",
    "invalid user",
    "authentication failure",
    "permission denied",
    "sudo: pam_unix",
    "segfault",
    "scan",
    "sqlmap",
    "nikto",
    "masscan",
    "directory traversal",
    "../",
]


def detect_log_type(line):
    """Return the log type for a line: auth, apache, syslog or unknown."""
    for name, pattern in PATTERNS.items():
        if pattern.match(line):
            return name
    return "unknown"


def parse_line(line):
    """Convert one raw log line into a structured entry.

    Unknown formats pass through untouched with ``type`` set to "unknown"
    so nothing gets silently dropped during an investigation.
    """
    line = line.strip()
    if not line:
        return {"raw": "", "type": "unknown", "suspicious": False}

    log_type = detect_log_type(line)
    pattern = PATTERNS.get(log_type)
    if pattern is None:
        return {"raw": line, "type": "unknown", "suspicious": False}

    match = pattern.match(line)
    if match is None:
        return {"raw": line, "type": log_type, "suspicious": False}

    entry = match.groupdict()
    entry["type"] = log_type
    entry["suspicious"] = any(
        keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS
    )
    return entry


def parse_file(filepath):
    """Parse every non-blank line of a log file into structured entries."""
    entries = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    entries.append(parse_line(line))
    except OSError as exc:
        print(f"error: cannot read {filepath}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return entries


def print_summary(entries):
    """Print a digest of totals, log types and suspicious events."""
    total = len(entries)
    suspicious = [entry for entry in entries if entry.get("suspicious")]

    type_counts = {}
    for entry in entries:
        log_type = entry.get("type", "unknown")
        type_counts[log_type] = type_counts.get(log_type, 0) + 1

    print(f"\nTotal log entries : {total}")
    print(f"Suspicious events : {len(suspicious)}")
    print(f"Log types         : {json.dumps(type_counts, indent=2)}")

    if suspicious:
        print("\n--- Suspicious entries ---")
        for entry in suspicious:
            message = (
                entry.get("message")
                or entry.get("request")
                or entry.get("raw")
            )
            print(f"  [{entry.get('type')}] {message}")


def main():
    """CLI entry point for the log parser."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-parser",
        description="Parse and classify raw log files into structured JSON",
    )
    cli.add_argument("--file", required=True, help="Path to the log file")
    cli.add_argument("--output", help="Write parsed entries to this JSON file")
    args = cli.parse_args()

    entries = parse_file(args.file)
    print_summary(entries)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(entries, handle, indent=2)
            print(f"\nSaved to {args.output}")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
