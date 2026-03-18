"""
Parser for Linux auth.log and syslog.
Handles SSH, sudo, su, PAM, cron auth events.
"""

import re
from datetime import datetime, timezone
from typing import Iterator, Optional
from core.models import LogEvent

# Compiled patterns for speed
_TIMESTAMP_FMT  = "%b %d %H:%M:%S"
_SSH_FAIL       = re.compile(r"Failed (password|publickey) for (?:invalid user )?(\S+) from ([\d.]+) port \d+")
_SSH_OK         = re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+) port \d+")
_SSH_INVALID    = re.compile(r"Invalid user (\S+) from ([\d.]+)")
_SSH_DISCONNECT = re.compile(r"Disconnected from (?:invalid user )?(\S+)? ?([\d.]+) port")
_SUDO_CMD       = re.compile(r"sudo:\s+(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.+)")
_SUDO_FAIL      = re.compile(r"sudo:\s+(\S+) : \d+ incorrect password")
_SU_BAD         = re.compile(r"su: FAILED SU \(to (\S+)\) (\S+) on")
_SU_OK          = re.compile(r"su: \(to (\S+)\) (\S+) on")
_PAM_FAIL       = re.compile(r"pam_unix\((\S+)\): authentication failure.*?user=(\S+)")
_BRUTE_NOVAL    = re.compile(r"message repeated (\d+) times")


def _parse_timestamp(year: int, raw_ts: str) -> datetime:
    try:
        dt = datetime.strptime(raw_ts.strip(), _TIMESTAMP_FMT)
        return dt.replace(year=year, tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_auth_log(path: str) -> Iterator[LogEvent]:
    year = datetime.now().year
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue

            # Extract timestamp (first 15 chars: "Jan  1 00:00:00")
            ts_str = line[:15]
            rest   = line[16:]
            ts     = _parse_timestamp(year, ts_str)

            # --- SSH failures ---
            m = _SSH_FAIL.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=m.group(3), user=m.group(2),
                    action="ssh_login", status="failure",
                    raw=line, log_type="auth",
                    extra={"method": m.group(1)},
                )
                continue

            # --- SSH success ---
            m = _SSH_OK.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=m.group(3), user=m.group(2),
                    action="ssh_login", status="success",
                    raw=line, log_type="auth",
                    extra={"method": m.group(1)},
                )
                continue

            # --- Invalid user ---
            m = _SSH_INVALID.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=m.group(2), user=m.group(1),
                    action="ssh_invalid_user", status="failure",
                    raw=line, log_type="auth",
                )
                continue

            # --- Sudo commands ---
            m = _SUDO_CMD.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=None, user=m.group(1),
                    action="sudo_command", status="success",
                    raw=line, log_type="auth",
                    extra={"target_user": m.group(2), "command": m.group(3).strip()},
                )
                continue

            # --- Sudo failure ---
            m = _SUDO_FAIL.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=None, user=m.group(1),
                    action="sudo_fail", status="failure",
                    raw=line, log_type="auth",
                )
                continue

            # --- su bad ---
            m = _SU_BAD.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=None, user=m.group(2),
                    action="su_fail", status="failure",
                    raw=line, log_type="auth",
                    extra={"target_user": m.group(1)},
                )
                continue

            # --- su ok ---
            m = _SU_OK.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=None, user=m.group(2),
                    action="su_success", status="success",
                    raw=line, log_type="auth",
                    extra={"target_user": m.group(1)},
                )
                continue

            # --- PAM failure ---
            m = _PAM_FAIL.search(rest)
            if m:
                yield LogEvent(
                    timestamp=ts, source_ip=None, user=m.group(2),
                    action="pam_auth_fail", status="failure",
                    raw=line, log_type="auth",
                    extra={"service": m.group(1)},
                )
                continue
