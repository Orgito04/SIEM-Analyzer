"""
Parser for Apache / Nginx access logs (Combined Log Format).
Also handles error logs for both servers.
"""

import re
from datetime import datetime, timezone
from typing import Iterator
from core.models import LogEvent

# Combined Log Format: IP - user [timestamp] "METHOD /path HTTP/x" status bytes "referer" "UA"
_COMBINED = re.compile(
    r'(?P<ip>[\d.a-fA-F:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

# Nginx error log
_NGINX_ERR = re.compile(
    r'(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
    r'\d+#\d+: \*?\d* ?(?P<msg>.+?)(?:, client: (?P<ip>[\d.]+))?(?:, server:.*)?$'
)

_TS_FMT_COMBINED = "%d/%b/%Y:%H:%M:%S %z"
_TS_FMT_NGINX    = "%Y/%m/%d %H:%M:%S"

# Status codes that matter for detection
_SUSPICIOUS_STATUS = {400, 401, 403, 404, 405, 429, 500, 501, 502, 503}
_SCAN_PATHS = re.compile(
    r"(?:\.php|\.asp|\.env|/admin|/wp-login|/phpmyadmin|/cgi-bin|"
    r"\.git/|/etc/passwd|/proc/self|\.htaccess|union.*select|"
    r"<script|javascript:|onload=|'--|DROP TABLE)", re.IGNORECASE
)


def _web_status(code: int) -> str:
    if code < 400:
        return "success"
    if code in (401, 403):
        return "forbidden"
    if code == 404:
        return "not_found"
    return "failure"


def parse_web_log(path: str) -> Iterator[LogEvent]:
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue

            # Try combined log format first
            m = _COMBINED.match(line)
            if m:
                try:
                    ts = datetime.strptime(m.group("ts"), _TS_FMT_COMBINED)
                except ValueError:
                    ts = datetime.now(timezone.utc)

                status_code = int(m.group("status"))
                path_val    = m.group("path")
                method      = m.group("method")
                ua          = m.group("ua") or ""
                user        = m.group("user") if m.group("user") != "-" else None

                suspicious_path = bool(_SCAN_PATHS.search(path_val + " " + ua))

                yield LogEvent(
                    timestamp=ts,
                    source_ip=m.group("ip"),
                    user=user,
                    action=f"http_{method.lower()}",
                    status=_web_status(status_code),
                    raw=line,
                    log_type="web",
                    extra={
                        "method":      method,
                        "path":        path_val,
                        "status_code": status_code,
                        "bytes":       m.group("bytes"),
                        "user_agent":  ua,
                        "referer":     m.group("referer") or "",
                        "suspicious":  suspicious_path,
                    },
                )
                continue

            # Try nginx error format
            m = _NGINX_ERR.match(line)
            if m:
                try:
                    ts = datetime.strptime(m.group("ts"), _TS_FMT_NGINX).replace(tzinfo=timezone.utc)
                except ValueError:
                    ts = datetime.now(timezone.utc)

                yield LogEvent(
                    timestamp=ts,
                    source_ip=m.group("ip"),
                    user=None,
                    action="nginx_error",
                    status="failure" if m.group("level") in ("error", "crit", "alert", "emerg") else "unknown",
                    raw=line,
                    log_type="web",
                    extra={"level": m.group("level"), "message": m.group("msg")},
                )
