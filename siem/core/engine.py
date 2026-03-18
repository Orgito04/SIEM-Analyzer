"""
SIEM Engine — Orchestrator
Wires parsers → detectors → alert manager into one callable API.
"""

import os
import sys
from pathlib import Path
from typing import Callable

from parsers.auth_parser    import parse_auth_log
from parsers.web_parser     import parse_web_log
from parsers.windows_parser import parse_windows_log
from parsers.json_parser    import parse_json_log

from detectors.brute_force  import BruteForceDetector
from detectors.privesc       import PrivescDetector
from detectors.anomaly       import AnomalyDetector

from core.alert_manager import AlertManager
from core.models        import LogEvent

# Auto-detect log type by filename/content
_PARSER_MAP = {
    "auth.log":    parse_auth_log,
    "syslog":      parse_auth_log,
    "secure":      parse_auth_log,
    "access.log":  parse_web_log,
    "access_log":  parse_web_log,
    "error.log":   parse_web_log,
    "error_log":   parse_web_log,
}

_EXT_MAP = {
    ".json": parse_json_log,
    ".xml":  parse_windows_log,
    ".evtx": parse_windows_log,
    ".log":  None,           # sniff content
    ".txt":  None,
}


def _detect_parser(path: str) -> Callable | None:
    p    = Path(path)
    name = p.name.lower()
    ext  = p.suffix.lower()

    # Exact filename match
    for pattern, parser in _PARSER_MAP.items():
        if pattern in name:
            return parser

    # Extension match
    if ext in _EXT_MAP:
        if _EXT_MAP[ext]:
            return _EXT_MAP[ext]
        # .log / .txt: sniff first 256 bytes
        try:
            with open(path, "r", errors="replace") as fh:
                peek = fh.read(256)
            if peek.lstrip().startswith("<"):
                return parse_windows_log
            if peek.lstrip().startswith(("{", "[")):
                return parse_json_log
            if "Failed password" in peek or "Accepted password" in peek or "sudo" in peek:
                return parse_auth_log
            if '"GET ' in peek or '"POST ' in peek or '" 200 ' in peek:
                return parse_web_log
        except Exception:
            pass

    return None


class SIEMEngine:
    """
    Main analysis engine.

    Usage:
        engine = SIEMEngine()
        engine.load_file("auth.log")
        engine.load_file("access.log")
        engine.load_file("events.json", parser="json")
        results = engine.analyze()
    """

    def __init__(self, output_dir: str = "reports"):
        self._events:  list[LogEvent] = []
        self._sources: list[str]      = []
        self.manager = AlertManager(output_dir=output_dir)

        self._brute   = BruteForceDetector()
        self._privesc = PrivescDetector()
        self._anomaly = AnomalyDetector()

    def load_file(self, path: str, parser: str | None = None) -> int:
        """
        Load and parse a log file. Returns number of events parsed.
        parser: 'auth' | 'web' | 'windows' | 'json' | None (auto-detect)
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Log file not found: {path}")

        # Select parser
        if parser:
            fn = {
                "auth":    parse_auth_log,
                "web":     parse_web_log,
                "windows": parse_windows_log,
                "json":    parse_json_log,
            }.get(parser)
            if not fn:
                raise ValueError(f"Unknown parser: {parser}. Use auth/web/windows/json")
        else:
            fn = _detect_parser(path)
            if not fn:
                raise ValueError(
                    f"Cannot auto-detect parser for '{path}'. "
                    f"Pass parser='auth'|'web'|'windows'|'json' explicitly."
                )

        before = len(self._events)
        try:
            for ev in fn(path):
                self._events.append(ev)
        except Exception as e:
            raise RuntimeError(f"Failed parsing '{path}': {e}") from e

        loaded = len(self._events) - before
        self._sources.append(path)
        return loaded

    def analyze(self) -> AlertManager:
        """Run all detectors against loaded events and return AlertManager."""
        if not self._events:
            return self.manager

        # Sort events by timestamp for accurate windowed detection
        events = sorted(self._events, key=lambda e: e.timestamp)

        # Feed all detectors
        self.manager.ingest(self._brute.feed(events))
        self.manager.ingest(self._privesc.feed(events))
        self.manager.ingest(self._anomaly.feed(events))

        return self.manager

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def sources(self) -> list[str]:
        return self._sources
