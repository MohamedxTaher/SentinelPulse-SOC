"""YAML-driven detection rules and the correlation engine that runs them."""

from soc.alert_rules.alert_engine import load_rules, run_engine, match_rule

__all__ = ["load_rules", "run_engine", "match_rule"]
