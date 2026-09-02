"""Threat intelligence enrichment for SentinelPulse SOC Analytics.

Extracts every unique source IP from parsed logs and checks each against
the AbuseIPDB reputation API. A high abuse confidence score turns a
"suspicious login" alert into a confirmed attack from a known hostile
source, which is often the deciding factor between monitor and block.

Requires the ``ABUSEIPDB_KEY`` environment variable. A free key can be
created at https://www.abuseipdb.com/register.

Usage:
    export ABUSEIPDB_KEY=your_key_here
    python soc/alert_rules/threat_intel.py --logs parsed.json

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 10
# Stay comfortably under AbuseIPDB's rate limit for free-tier keys.
REQUEST_DELAY_SECONDS = 1.0
VERDICT_THRESHOLDS = {"malicious": 80, "suspicious": 40}

CATEGORY_NAMES = {
    "1": "DNS Compromise", "2": "DNS Poisoning", "3": "Fraud Orders",
    "4": "DDoS Attack", "5": "FTP Brute-Force", "6": "Ping of Death",
    "7": "Phishing", "8": "Fraud VoIP", "9": "Open Proxy",
    "10": "Web Spam", "11": "Email Spam", "12": "Blog Spam",
    "13": "VPN IP", "14": "Port Scan", "15": "Hacking",
    "16": "SQL Injection", "17": "Spoofing", "18": "Brute Force",
    "19": "Bad Web Bot", "20": "Exploited Host", "21": "Web App Attack",
    "22": "SSH", "23": "IoT Targeted",
}


def _is_ipv4(candidate):
    """Cheap validation: four dot-separated octets in range."""
    parts = candidate.split(".")
    return (
        len(parts) == 4
        and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    )


def get_unique_ips(logs):
    """Collect every distinct source IP across log entries and messages."""
    ips = set()
    for entry in logs:
        ip = entry.get("ip")
        if ip and ip not in ("", "-"):
            ips.add(ip)

        message = entry.get("message", "")
        parts = message.split("from ")
        if len(parts) > 1:
            candidate = parts[1].split()[0]
            if _is_ipv4(candidate):
                ips.add(candidate)
    return ips


def check_ip(ip, api_key):
    """Query AbuseIPDB for one address, returning parsed JSON or an error."""
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    })
    request = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{params}",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}: {exc.reason}"}
    except (urllib.error.URLError, TimeoutError) as exc:
        return {"error": f"connection failed: {exc}"}


def _verdict(score):
    """Map an abuse confidence score to an operational verdict."""
    if score >= VERDICT_THRESHOLDS["malicious"]:
        return "malicious", "BLOCK RECOMMENDED"
    if score >= VERDICT_THRESHOLDS["suspicious"]:
        return "suspicious", "monitor closely"
    return "clean", "no action required"


def print_results(results):
    """Render the enrichment table with score, reports and categories."""
    print(f"\nThreat Intel Results — {len(results)} IP(s) checked\n")
    print(f"{'IP':<20} {'Score':>6}  {'Reports':>8}  {'Categories'}")
    print("-" * 78)

    for ip, data in results.items():
        if "error" in data:
            print(f"{ip:<20}  Error: {data['error']}")
            continue

        payload = data.get("data", {})
        score = payload.get("abuseConfidenceScore", 0)
        reports = payload.get("totalReports", 0)
        category_ids = payload.get("abuseConfidenceCategories") or []
        categories = (
            ", ".join(
                CATEGORY_NAMES.get(str(cid), str(cid))
                for cid in category_ids
            )
            or payload.get("usageType", "Unknown")
        )
        _, recommendation = _verdict(score)
        flag = " !" if score > 50 else ""
        print(
            f"{ip:<20} {score:>6}%  {reports:>8}  "
            f"{categories}{flag}"
        )

    malicious = [
        ip for ip, data in results.items()
        if "error" not in data
        and data.get("data", {}).get("abuseConfidenceScore", 0)
        >= VERDICT_THRESHOLDS["malicious"]
    ]
    if malicious:
        print(f"\n{len(malicious)} malicious source(s):")
        for ip in malicious:
            print(f"  {ip} — {_verdict(results[ip]['data']['abuseConfidenceScore'])[1]}")


def main():
    """CLI entry point for the threat intel enrichment pass."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-intel",
        description="Check IPs from parsed logs against AbuseIPDB",
    )
    cli.add_argument("--logs", required=True, help="Parsed JSON log file")
    args = cli.parse_args()

    api_key = os.environ.get("ABUSEIPDB_KEY")
    if not api_key:
        print("error: ABUSEIPDB_KEY environment variable not set.")
        print("Get a free key at https://www.abuseipdb.com/register")
        raise SystemExit(1)

    try:
        with open(args.logs, "r", encoding="utf-8") as handle:
            logs = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {args.logs}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    ips = get_unique_ips(logs)
    if not ips:
        print("No IPs found in logs.")
        return

    print(f"Checking {len(ips)} IP(s)...")
    results = {}
    for index, ip in enumerate(sorted(ips)):
        if index > 0:
            time.sleep(REQUEST_DELAY_SECONDS)
        results[ip] = check_ip(ip, api_key)

    print_results(results)


if __name__ == "__main__":
    main()
