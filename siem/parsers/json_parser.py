"""
Generic JSON / NDJSON log parser.
Accepts any JSON log where fields are configurable via field_map.
"""

import json
from datetime import datetime, timezone
from typing import Iterator
from core.models import LogEvent

DEFAULT_FIELD_MAP = {
    "timestamp":  ["timestamp", "ts", "time", "@timestamp", "date", "datetime"],
    "source_ip":  ["source_ip", "src_ip", "ip", "client_ip", "remote_addr", "host"],
    "user":       ["user", "username", "user_name", "actor", "account"],
    "action":     ["action", "event", "event_type", "type", "category"],
    "status":     ["status", "result", "outcome", "state"],
}

_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%d/%b/%Y:%H:%M:%S %z",
]


def _extract(record: dict, candidates: list[str]) -> str | None:
    for key in candidates:
        val = record.get(key)
        if val is not None:
            return str(val)
    # case-insensitive fallback
    lower = {k.lower(): v for k, v in record.items()}
    for key in candidates:
        val = lower.get(key.lower())
        if val is not None:
            return str(val)
    return None


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    # Unix epoch
    try:
        epoch = float(raw)
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    # String formats
    for fmt in _TS_FMTS:
        try:
            dt = datetime.strptime(raw[:26], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def parse_json_log(path: str, field_map: dict | None = None) -> Iterator[LogEvent]:
    """
    Parse NDJSON (one JSON object per line) or a JSON array file.
    field_map overrides DEFAULT_FIELD_MAP for custom log schemas.
    """
    fm = {**DEFAULT_FIELD_MAP, **(field_map or {})}

    with open(path, "r", errors="replace") as fh:
        content = fh.read().strip()

    # JSON array
    if content.startswith("["):
        try:
            records = json.loads(content)
        except json.JSONDecodeError:
            records = []
    else:
        # NDJSON — one object per line
        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for record in records:
        if not isinstance(record, dict):
            continue

        ts     = _parse_ts(_extract(record, fm["timestamp"]))
        ip     = _extract(record, fm["source_ip"])
        user   = _extract(record, fm["user"])
        action = _extract(record, fm["action"]) or "unknown"
        status = _extract(record, fm["status"]) or "unknown"

        # Everything that's not a mapped field goes into extra
        mapped_keys = {k for keys in fm.values() for k in keys}
        extra = {k: v for k, v in record.items() if k not in mapped_keys}

        yield LogEvent(
            timestamp=ts,
            source_ip=ip,
            user=user,
            action=action,
            status=status,
            raw=json.dumps(record)[:500],
            log_type="json",
            extra=extra,
        )
