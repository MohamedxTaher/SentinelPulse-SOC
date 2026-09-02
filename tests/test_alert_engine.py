import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from soc.alert_rules.alert_engine import match_rule, run_engine


def make_rule(contains=None, equals=None, log_type="auth", threshold=1):
    condition = {"field": "message", "threshold": threshold}
    if contains:
        condition["contains"] = contains
    if equals:
        condition["equals"] = equals
    return {
        "id": "TEST-001",
        "name": "Test Rule",
        "log_type": log_type,
        "condition": condition,
        "severity": "high",
        "action": "alert",
        "mitre": {},
    }


def test_match_rule_contains():
    rule = make_rule(contains="Failed password")
    entry = {"type": "auth", "message": "Failed password for root from 10.0.0.1"}
    assert match_rule(rule, entry) is True


def test_match_rule_no_match():
    rule = make_rule(contains="Failed password")
    entry = {"type": "auth", "message": "Accepted password for alice"}
    assert match_rule(rule, entry) is False


def test_match_rule_equals():
    rule = {"condition": {"field": "status", "equals": "401", "threshold": 1}}
    entry = {"type": "apache", "status": "401"}
    assert match_rule(rule, entry) is True


def test_run_engine_triggers_alert():
    rule = make_rule(contains="Failed password", threshold=1)
    logs = [{"type": "auth", "message": "Failed password for root", "suspicious": True}]
    alerts = run_engine(logs, [rule])
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TEST-001"


def test_run_engine_threshold_not_reached():
    rule = make_rule(contains="Failed password", threshold=3)
    logs = [
        {"type": "auth", "message": "Failed password for root", "suspicious": True},
        {"type": "auth", "message": "Failed password for root", "suspicious": True},
    ]
    alerts = run_engine(logs, [rule])
    assert len(alerts) == 0
