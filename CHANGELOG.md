# Changelog

All notable changes to SentinelPulse SOC Analytics are documented here.

## [2.0.0] - 2026-09-02 — "SentinelPulse" rebrand

The project was renamed to **SentinelPulse SOC Analytics** and rebuilt as a production-quality detection engineering toolkit.

### Added
- New detection rules: SQL injection probe, Nikto fingerprint, masscan sweep, sensitive file access (`/.env`), XSS payload — 15 rules total across 7 MITRE tactics
- Web alert console (`dashboard/index.html`) with severity, technique and status filtering plus a MITRE technique heatmap
- Interactive MITRE ATT&CK matrix in the field guide
- Package structure: `__init__.py` modules so `soc.*` imports resolve cleanly
- Status-code constraints in rule conditions (401-only credential stuffing detection)
- Severity-ordered, deduplicated alert output
- Rate limiting, timeouts and IPv4 validation in the threat intel module

### Changed
- Full frontend redesign: obsidian dark theme, glassmorphic surfaces, cyan/emerald accents, Inter + Fira Code typography
- Refactored all backend modules to PEP 8 with docstrings and consistent error handling
- Directory names use underscores (`alert_rules`, `log_parser`) so tests can import them
- Brute force detector now uses a linear two-pointer sweep instead of quadratic window counting
- Quiz rebuilt with animated progress, SVG score ring and per-category breakdown

### Fixed
- Test imports (`soc.alert_rules`, `soc.log_parser`) that could never resolve against hyphenated directory names

## [1.1.0] - 2026-03-16
- Added MITRE ATT&CK mapping to all detection rules
- Added AbuseIPDB threat intelligence lookup
- Added pytest test suite (11 tests)
- Added CONTRIBUTING.md

## [1.0.0] - 2026-03-14
- Initial release
- Log parser for syslog, apache and auth formats
- Alert engine with 6 detection rules
- Terminal dashboard
- Incident response playbook
