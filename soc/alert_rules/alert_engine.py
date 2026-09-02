"""Detection rule engine for SentinelPulse SOC Analytics.

Runs YAML-defined rules against parsed log entries and emits MITRE
ATT&CK-tagged alerts. Rules support field matching (contains/equals),
status-code constraints, per-rule thresholds and a built-in brute force
correlation layer that counts failed logins per source IP across the
whole batch.

Usage:
    python soc/alert_rules/alert_engine.py \
        --logs parsed.json --rules soc/alert_rules/rules.yaml \
        --output alerts.log

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime

import yaml

# Alerts are reported highest severity first so triage starts at the top.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Failed-login correlation: how many attempts from one IP before we treat
# it as coordinated brute force rather than a fat-fingered user.
BRUTE_FORCE_THRESHOLD = 3


def load_rules(rules_file):
    """Load detection rules from a YAML file."""
    try:
        with open(rules_file, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        print(f"error: cannot read {rules_file}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except yaml.YAMLError as exc:
        print(f"error: invalid YAML in {rules_file}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    rules = data.get("rules", []) if isinstance(data, dict) else None
    if not rules:
        print(f"error: no rules found in {rules_file}", file=sys.stderr)
        raise SystemExit(1)
    return rules


def load_logs(log_file):
    """Load parsed log entries from a JSON file."""
    try:
        with open(log_file, "r", encoding="utf-8") as handle:
            logs = json.load(handle)
    except OSError as exc:
        print(f"error: cannot read {log_file}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {log_file}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if not isinstance(logs, list):
        print(f"error: {log_file} does not contain a log array", file=sys.stderr)
        raise SystemExit(1)
    return logs


def _extract_ip(message):
    """Pull the source IPv4 address out of an SSH auth failure message."""
    parts = message.lower().split("from ")
    if len(parts) < 2:
        return None
    candidate = parts[1].split()[0]
    if candidate.count(".") == 3 and all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in candidate.split(".")
    ):
        return candidate
    return None


def match_rule(rule, entry):
    """Evaluate one rule's condition block against one log entry."""
    condition = rule.get("condition", {})
    field = condition.get("field")
    if field is None:
        return False

    value = str(entry.get(field, "")).lower()

    if "contains" in condition:
        matched = condition["contains"].lower() in value
    elif "equals" in condition:
        matched = value == condition["equals"].lower()
    else:
        matched = False

    # Some web rules only fire on a specific HTTP status (e.g. 401s on
    # /login) so benign 200s on the same path don't inflate the count.
    if matched and "status_code" in condition:
        status = str(entry.get("status", ""))
        matched = status == str(condition["status_code"])

    return matched


def _brute_force_alerts(logs):
    """Correlate failed logins per source IP across the whole batch."""
    ip_counts = defaultdict(int)
    for entry in logs:
        message = entry.get("message") or ""
        lowered = message.lower()
        if "failed password" in lowered or "invalid user" in lowered:
            ip = _extract_ip(message)
            if ip:
                ip_counts[ip] += 1

    alerts = []
    for ip, count in ip_counts.items():
        if count < BRUTE_FORCE_THRESHOLD:
            continue
        severity = "critical" if count >= 2 * BRUTE_FORCE_THRESHOLD else "high"
        alerts.append({
            "rule_id": "RULE-BF",
            "rule_name": "Brute Force Detected",
            "severity": severity,
            "action": "alert",
            "mitre": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
            },
            "matched_entry": {
                "type": "auth",
                "message": (
                    f"Source IP {ip} had {count} failed login attempts"
                ),
            },
            "threshold_hit": count,
        })
    return alerts


def run_engine(logs, rules):
    """Run every rule against every entry and return triggered alerts."""
    triggered = []
    counts = defaultdict(int)

    for entry in logs:
        for rule in rules:
            if entry.get("type") != rule.get("log_type"):
                continue
            if not match_rule(rule, entry):
                continue

            counts[rule["id"]] += 1
            threshold = rule["condition"].get("threshold", 1)
            if counts[rule["id"]] >= threshold:
                triggered.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule.get("severity", "medium"),
                    "action": rule.get("action", "log"),
                    "mitre": rule.get("mitre", {}),
                    "matched_entry": entry,
                    "threshold_hit": counts[rule["id"]],
                })

    triggered.extend(_brute_force_alerts(logs))
    return triggered


def _dedupe(alerts):
    """Collapse duplicate (rule, message) pairs from repeated triggers."""
    seen = set()
    unique = []
    for alert in alerts:
        key = (
            alert["rule_id"],
            str(alert["matched_entry"].get("message", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)
    return unique


def format_alerts(alerts):
    """Render alerts as the human-readable report shown in the console."""
    if not alerts:
        return "No alerts triggered."

    lines = [f"\n{len(alerts)} alert(s) triggered:\n"]
    for alert in alerts:
        mitre = alert.get("mitre", {})
        lines.append(
            f"[{alert['severity'].upper()}] "
            f"{alert['rule_name']} ({alert['rule_id']})"
        )
        if mitre:
            lines.append(
                f"  MITRE ATT&CK : {mitre.get('technique_id')} - "
                f"{mitre.get('technique_name')} ({mitre.get('tactic')})"
            )
        lines.append(f"  Action       : {alert['action']}")
        entry = alert["matched_entry"]
        message = (
            entry.get("message") or entry.get("request") or entry.get("raw")
        )
        lines.append(f"  Log entry    : {message}")
        lines.append("")
    return "\n".join(lines)


def print_alerts(alerts, output_file=None):
    """Print the alert report and optionally append it to a log file."""
    alerts = _dedupe(alerts)
    alerts.sort(key=lambda alert: SEVERITY_ORDER.get(alert["severity"], 99))

    output = format_alerts(alerts)
    print(output)

    if output_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(output_file, "a", encoding="utf-8") as handle:
                handle.write(f"\n=== Run: {timestamp} ===\n")
                handle.write(output)
            print(f"Alerts appended to {output_file}")
        except OSError as exc:
            print(
                f"error: cannot write {output_file}: {exc}", file=sys.stderr
            )


def main():
    """CLI entry point for the detection engine."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-engine",
        description="Run YAML detection rules against parsed logs",
    )
    cli.add_argument("--logs", required=True, help="Parsed JSON log file")
    cli.add_argument("--rules", required=True, help="Detection rules YAML")
    cli.add_argument("--output", help="Append alerts to this log file")
    args = cli.parse_args()

    rules = load_rules(args.rules)
    logs = load_logs(args.logs)
    alerts = run_engine(logs, rules)
    print_alerts(alerts, output_file=args.output)


if __name__ == "__main__":
    main()
