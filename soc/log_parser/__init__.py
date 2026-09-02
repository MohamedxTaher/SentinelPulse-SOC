"""Log ingestion and classification for syslog, Apache and auth formats."""

from soc.log_parser.parser import parse_file, parse_line, detect_log_type

__all__ = ["parse_file", "parse_line", "detect_log_type"]
