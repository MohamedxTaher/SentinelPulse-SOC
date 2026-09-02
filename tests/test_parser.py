import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from soc.log_parser.parser import parse_line, detect_log_type


def test_detects_auth_log():
    line = "Mar 14 08:12:01 webserver sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    assert detect_log_type(line) in ("auth", "syslog")


def test_detects_apache_log():
    line = '192.168.1.1 - - [14/Mar/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
    assert detect_log_type(line) == "apache"


def test_flags_failed_password_as_suspicious():
    line = "Mar 14 08:12:01 webserver sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    entry = parse_line(line)
    assert entry["suspicious"] is True


def test_normal_login_not_suspicious():
    line = "Mar 14 08:15:00 webserver sshd[1235]: Accepted password for alice from 10.0.0.5 port 45678 ssh2"
    entry = parse_line(line)
    assert entry["suspicious"] is False


def test_invalid_user_flagged():
    line = "Mar 14 08:12:09 webserver sshd[1234]: Invalid user admin from 192.168.1.100"
    entry = parse_line(line)
    assert entry["suspicious"] is True


def test_unknown_line_returned_safely():
    line = "this is not a real log line"
    entry = parse_line(line)
    assert entry["type"] == "unknown"
    assert entry["suspicious"] is False
