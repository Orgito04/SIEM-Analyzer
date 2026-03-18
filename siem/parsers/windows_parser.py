"""
Parser for Windows Event Logs.
Supports: exported .evtx XML dumps, plain text Security log exports,
and JSON structured exports from tools like wevtutil or Get-WinEvent.
"""

import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterator
from core.models import LogEvent

# Key Windows Security Event IDs
EVENT_IDS = {
    4624: ("logon_success",     "success"),
    4625: ("logon_failure",     "failure"),
    4634: ("logoff",            "success"),
    4648: ("logon_explicit",    "success"),   # Logon using explicit creds
    4672: ("special_privileges","success"),   # Admin logon
    4688: ("process_created",   "success"),
    4698: ("scheduled_task",    "success"),   # Task created
    4720: ("account_created",   "success"),
    4722: ("account_enabled",   "success"),
    4724: ("password_reset",    "success"),
    4728: ("group_member_add",  "success"),   # Added to privileged group
    4732: ("group_member_add",  "success"),
    4756: ("group_member_add",  "success"),
    4768: ("kerberos_tgt",      "success"),
    4769: ("kerberos_service",  "success"),
    4771: ("kerberos_preauth",  "failure"),
    4776: ("ntlm_auth",         "unknown"),
    4798: ("user_enum",         "success"),
    4799: ("group_enum",        "success"),
    5140: ("share_access",      "success"),
    7045: ("service_installed", "success"),
}

# Text-format pattern: "Date/Time  EventID  Source  ...  Description"
_TEXT_LINE = re.compile(
    r"(?P<ts>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))"
    r".*?(?P<evtid>\d{4,5})"
)
_XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_win_ts(ts_str: str) -> datetime:
    fmts = [
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(ts_str.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _event_from_id(event_id: int, ts: datetime, source_ip: str | None,
                   user: str | None, raw: str, extra: dict) -> LogEvent:
    action, status = EVENT_IDS.get(event_id, (f"event_{event_id}", "unknown"))
    return LogEvent(
        timestamp=ts, source_ip=source_ip, user=user,
        action=action, status=status,
        raw=raw, log_type="windows",
        extra={"event_id": event_id, **extra},
    )


def parse_windows_evtx_xml(path: str) -> Iterator[LogEvent]:
    """Parse exported XML from wevtutil or Event Viewer."""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        # Try wrapping in a root element (some exports lack one)
        with open(path, "r", errors="replace") as fh:
            content = "<Events>" + fh.read() + "</Events>"
        root = ET.fromstring(content)

    tag_event = root.tag.split("}")[-1]
    events = root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event") or \
             root.findall(".//Event")

    for evt in events:
        try:
            sys_el  = evt.find("{http://schemas.microsoft.com/win/2004/08/events/event}System") or \
                      evt.find("System")
            data_el = evt.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData") or \
                      evt.find("EventData")

            eid_el  = sys_el.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID") or \
                      sys_el.find("EventID")
            ts_el   = sys_el.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated") or \
                      sys_el.find(".//TimeCreated")

            event_id = int(eid_el.text)
            ts_str   = ts_el.get("SystemTime", "") if ts_el is not None else ""
            ts       = _parse_win_ts(ts_str)

            # Extract named data fields
            extra = {}
            user, source_ip = None, None
            if data_el is not None:
                for d in data_el:
                    name = d.get("Name", "")
                    val  = (d.text or "").strip()
                    if not val or val in ("-", "NULL", "0x0"):
                        continue
                    extra[name] = val
                    if name in ("TargetUserName", "SubjectUserName"):
                        user = val
                    if name == "IpAddress":
                        source_ip = val

            yield _event_from_id(event_id, ts, source_ip, user,
                                  ET.tostring(evt, encoding="unicode")[:300], extra)
        except Exception:
            continue


def parse_windows_json(path: str) -> Iterator[LogEvent]:
    """Parse JSON exports (e.g. PowerShell Get-WinEvent | ConvertTo-Json)."""
    with open(path, "r", errors="replace") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError:
            return

    if isinstance(data, dict):
        data = [data]

    for record in data:
        try:
            event_id  = int(record.get("Id", record.get("EventID", 0)))
            ts_str    = record.get("TimeCreated", record.get("TimeGenerated", ""))
            ts        = _parse_win_ts(str(ts_str))
            props     = record.get("Properties", record.get("Message", {}))
            user      = record.get("UserId", None)
            source_ip = record.get("IpAddress", None)

            yield _event_from_id(event_id, ts, source_ip, user,
                                  json.dumps(record)[:300],
                                  {"raw_props": str(props)[:200]})
        except Exception:
            continue


def parse_windows_log(path: str) -> Iterator[LogEvent]:
    """Auto-detect format: XML, JSON, or plain text."""
    with open(path, "r", errors="replace") as fh:
        peek = fh.read(512).lstrip()

    if peek.startswith("<"):
        yield from parse_windows_evtx_xml(path)
    elif peek.startswith("[") or peek.startswith("{"):
        yield from parse_windows_json(path)
    else:
        # Plain text: best-effort extraction
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = _TEXT_LINE.search(line)
                if m:
                    ts  = _parse_win_ts(m.group("ts"))
                    eid = int(m.group("evtid"))
                    yield _event_from_id(eid, ts, None, None, line.strip(), {})
