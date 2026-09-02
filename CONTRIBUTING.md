# Contributing

Thanks for taking a look at SentinelPulse. Here is how to get involved.

## Getting set up

```bash
git clone https://github.com/MohamedxTaher/SentinelPulse-SOC.git
cd SentinelPulse-SOC
pip install -r requirements.txt
```

## Running the tests

```bash
pytest tests/
```

All tests should pass before you open a pull request. New rules should come with tests covering the match logic and threshold behaviour.

## Adding a new detection rule

Rules live in `soc/alert_rules/rules.yaml`. Each rule needs:

- A unique ID (e.g. `RULE-016`)
- A name and a `log_type` it applies to (`syslog`, `apache` or `auth`)
- A condition with a field, match type (`contains` or `equals`), optional `status_code` and optional `threshold`
- A severity level: `low`, `medium`, `high` or `critical`
- An action: `log`, `alert` or `block`
- A MITRE ATT&CK technique ID and tactic

Rule conditions are evaluated by `match_rule()` in `soc/alert_rules/alert_engine.py` — read it before writing anything exotic.

## Adding a new log source

The parser classifies lines via the ordered regex `PATTERNS` dict in `soc/log_parser/parser.py`. Add a pattern, keep the most specific formats first, and update `SUSPICIOUS_KEYWORDS` if the source has its own attack signatures.

## Style

- PEP 8, 100-character lines
- Docstrings on every public function — write them like you'd explain the code to a new analyst, not like a restatement of the function name
- Comments explain *why*, never *what*

## Reporting a bug

Open an issue describing what happened, what you expected, and how to reproduce it. Include the log line that triggered it if the problem is in the detection pipeline.
