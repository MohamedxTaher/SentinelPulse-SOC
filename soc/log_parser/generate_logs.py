"""Synthetic log generator for SentinelPulse SOC Analytics.

Produces realistic sample logs mixing legitimate traffic with attack
patterns — SSH brute force bursts, credential stuffing, web probes and
host-level events — so the detection pipeline can be exercised without
touching production data. Used by the daily GitHub Actions scan.

Usage:
    python soc/log_parser/generate_logs.py

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import os
import random
from datetime import datetime, timedelta

USERNAMES = [
    "root", "admin", "user", "ubuntu", "postgres",
    "deploy", "git", "test", "oracle", "nagios", "jenkins",
]
INVALID_USERS = [
    "oracle", "ftpuser", "nagios", "jenkins",
    "hadoop", "elasticsearch",
]
SUSPICIOUS_IPS = [
    "45.33.32.156", "185.220.101.45", "198.20.69.74",
    "192.168.1.100", "10.0.0.99", "89.248.167.131", "194.165.16.11",
]
CLEAN_IPS = ["10.0.0.5", "172.16.0.10", "192.168.0.50", "192.168.1.10"]
APACHE_PATHS = [
    "/index.html", "/login", "/admin", "/api/v1/users", "/.env",
    "/wp-login.php", "/phpmyadmin", "/../etc/passwd", "/api/v1/admin",
    "/config.php", "/login?user=admin'--", "/search?q=<script>alert(1)</script>",
]
USER_AGENTS = [
    "Mozilla/5.0", "sqlmap/1.7", "curl/7.68.0",
    "python-requests/2.28", "Nikto/2.1.6", "masscan/1.0",
]
HOSTNAME = "webserver"


def _syslog_ts(offset_minutes=0):
    """Render a syslog-style timestamp some minutes in the past."""
    moment = datetime.now() - timedelta(minutes=offset_minutes)
    return moment.strftime("%b %d %H:%M:%S")


def _apache_ts():
    """Render an Apache-style timestamp for right now."""
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


def _pid():
    return random.randint(1000, 9999)


def _port():
    return random.randint(40000, 65000)


def make_failed_ssh(ip, offset=0):
    username = random.choice(USERNAMES)
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} sshd[{_pid()}]: "
        f"Failed password for {username} from {ip} port {_port()} ssh2"
    )


def make_root_ssh(ip, offset=0):
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} sshd[{_pid()}]: "
        f"Failed password for root from {ip} port {_port()} ssh2"
    )


def make_invalid_user(ip, offset=0):
    username = random.choice(INVALID_USERS)
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} sshd[{_pid()}]: "
        f"Invalid user {username} from {ip}"
    )


def make_accepted_ssh(offset=0):
    ip = random.choice(CLEAN_IPS)
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} sshd[{_pid()}]: "
        f"Accepted publickey for deploy from {ip} port {_port()} ssh2"
    )


def make_sudo_failure(offset=0):
    uid = random.randint(1001, 1005)
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} sudo[{_pid()}]: "
        f"pam_unix(sudo:auth): authentication failure; logname= uid={uid}"
    )


def make_apache(ip, path, status, user_agent=None, offset=0):
    if user_agent is None:
        user_agent = random.choice(USER_AGENTS)
    size = random.randint(200, 5000)
    return (
        f'{ip} - - [{_apache_ts()}] "GET {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def make_segfault(offset=0):
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} kernel: program[{_pid()}]: "
        f"segfault at 0 ip 00007f rsp 00007f error 4"
    )


def make_port_scan(ip, offset=0):
    return (
        f"{_syslog_ts(offset)} {HOSTNAME} kernel: "
        f"[UFW BLOCK] IN=eth0 SRC={ip} SCAN flags=S"
    )


def generate():
    """Build one mixed-bag log batch: attacks woven into normal traffic."""
    lines = []
    attack_ip = random.choice(SUSPICIOUS_IPS)
    offset = 0

    # SSH brute force burst — clustered in time so the sliding window
    # detector sees the density, not just the total count.
    burst = random.randint(4, 9)
    for _ in range(burst):
        offset += random.randint(0, 1)
        if random.random() > 0.6:
            lines.append(make_root_ssh(attack_ip, offset))
        else:
            lines.append(make_failed_ssh(attack_ip, offset))

    # Invalid user probes, typical of username enumeration.
    for _ in range(random.randint(1, 3)):
        offset += 1
        lines.append(make_invalid_user(attack_ip, offset))

    # Privilege escalation attempt.
    offset += random.randint(1, 4)
    lines.append(make_sudo_failure(offset))

    # A legitimate login for contrast.
    offset += random.randint(1, 3)
    lines.append(make_accepted_ssh(offset))

    # Web tier: normal browsing first...
    web_ip = random.choice(SUSPICIOUS_IPS)
    for path in ["/index.html", "/about", "/contact"]:
        lines.append(
            make_apache(random.choice(CLEAN_IPS), path, 200, "Mozilla/5.0")
        )

    # ...then the same source hammering the login endpoint (401s),
    # probing admin paths and attempting directory traversal.
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/login", 401, "Mozilla/5.0"))
    lines.append(make_apache(web_ip, "/admin", 403))
    lines.append(make_apache(web_ip, "/../etc/passwd", 400))

    # Automated scanner fingerprint.
    sqli_ip = random.choice(SUSPICIOUS_IPS)
    lines.append(
        make_apache(sqli_ip, "/search?q=1' OR '1'='1", 200, "sqlmap/1.7")
    )

    # Occasional host-level noise.
    if random.random() > 0.4:
        lines.append(make_segfault())
    if random.random() > 0.5:
        lines.append(make_port_scan(random.choice(SUSPICIOUS_IPS)))

    random.shuffle(lines)
    return "\n".join(lines) + "\n"


def main():
    """CLI entry point: write a fresh sample.log next to this module."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-genlogs",
        description="Generate a realistic mixed-traffic sample log file",
    )
    cli.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "sample.log"),
        help="Destination path for the generated log file",
    )
    args = cli.parse_args()

    content = generate()
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(f"Generated {len(content.splitlines())} log lines -> {args.output}")


if __name__ == "__main__":
    main()
