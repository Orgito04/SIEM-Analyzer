"""
Privilege Escalation Detector
Detects: sudo abuse, su to root, admin group additions, sensitive commands,
         Windows special privilege logon, scheduled task creation, service installs.
"""

import uuid
from collections import defaultdict
from datetime import datetime
from core.models import LogEvent, Alert, Severity

# Commands that are high-risk when run via sudo
_DANGEROUS_CMDS = {
    "/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/python3",
    "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/vim", "/usr/bin/nano",
    "/bin/chmod", "/bin/chown", "/usr/bin/passwd", "/usr/sbin/useradd",
    "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/find",
    "/usr/bin/awk", "/usr/bin/nmap", "/sbin/iptables", "/usr/bin/dd",
    "nc", "netcat", "wget", "curl", "base64",
}

_SENSITIVE_PATHS = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/", "/home/", ".ssh/", "authorized_keys",
    "/var/log/auth", "id_rsa",
)

# Windows privileged groups
_PRIV_GROUPS = {
    "Administrators", "Domain Admins", "Enterprise Admins",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Server Operators", "Power Users",
}

# Windows event IDs that indicate privilege escalation
_PRIV_EVENTS = {4672, 4728, 4732, 4756, 4698, 7045}


class PrivescDetector:

    def __init__(self):
        # Track sudo activity per user
        self._sudo_cmds:      defaultdict[str, list] = defaultdict(list)
        self._sudo_root:      defaultdict[str, int]  = defaultdict(int)
        self._su_root:        defaultdict[str, int]  = defaultdict(int)
        self._group_adds:     defaultdict[str, list] = defaultdict(list)
        self._emitted: set = set()

    def feed(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for ev in events:
            alerts.extend(self._check_event(ev))

        return alerts

    def _check_event(self, ev: LogEvent) -> list[Alert]:
        results = []

        # ── Linux sudo commands ──────────────────────────────────────────
        if ev.action == "sudo_command" and ev.status == "success":
            user       = ev.user or "unknown"
            target     = ev.extra.get("target_user", "")
            cmd        = ev.extra.get("command", "")
            cmd_base   = cmd.split()[0] if cmd else ""

            self._sudo_cmds[user].append((ev.timestamp, cmd))

            # sudo to root with dangerous command
            if target == "root":
                self._sudo_root[user] += 1

                is_dangerous = (
                    cmd_base in _DANGEROUS_CMDS or
                    any(p in cmd for p in _SENSITIVE_PATHS)
                )

                if is_dangerous:
                    key = f"sudo_dangerous_{user}_{cmd_base}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        results.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="PrivEsc",
                            severity=Severity.HIGH,
                            title=f"Dangerous sudo command by '{user}'",
                            description=(
                                f"User '{user}' ran '{cmd_base}' as root via sudo. "
                                f"This command can be abused for shell escape or data access."
                            ),
                            source_ip=ev.source_ip,
                            user=user,
                            timestamp=ev.timestamp,
                            event_count=1,
                            evidence=[f"sudo -u root {cmd}"],
                            mitre_tactic="Privilege Escalation",
                            mitre_id="T1548.003",
                        ))

                # Repeated sudo-to-root
                if self._sudo_root[user] == 10:
                    key = f"sudo_freq_{user}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        results.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="PrivEsc",
                            severity=Severity.MEDIUM,
                            title=f"High sudo frequency for '{user}'",
                            description=f"'{user}' has run {self._sudo_root[user]} sudo-as-root commands.",
                            source_ip=ev.source_ip,
                            user=user,
                            timestamp=ev.timestamp,
                            event_count=self._sudo_root[user],
                            evidence=[cmd for _, cmd in self._sudo_cmds[user][-5:]],
                            mitre_tactic="Privilege Escalation",
                            mitre_id="T1548.003",
                        ))

        # ── su to root ───────────────────────────────────────────────────
        elif ev.action == "su_success":
            user   = ev.user or "unknown"
            target = ev.extra.get("target_user", "")
            if target == "root":
                self._su_root[user] += 1
                sev = Severity.HIGH if self._su_root[user] == 1 else Severity.MEDIUM
                key = f"su_root_{user}_{self._su_root[user]}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="PrivEsc",
                        severity=sev,
                        title=f"User '{user}' switched to root (su)",
                        description=f"Direct root shell obtained via su. Occurrence #{self._su_root[user]}.",
                        source_ip=ev.source_ip,
                        user=user,
                        timestamp=ev.timestamp,
                        event_count=self._su_root[user],
                        evidence=[ev.raw],
                        mitre_tactic="Privilege Escalation",
                        mitre_id="T1548",
                    ))

        # ── Windows special privileges logon ─────────────────────────────
        elif ev.action == "special_privileges" and ev.extra.get("event_id") == 4672:
            user = ev.user or "unknown"
            if user.lower() not in ("system", "network service", "local service", ""):
                key = f"winpriv_{user}_{ev.timestamp.date()}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="PrivEsc",
                        severity=Severity.MEDIUM,
                        title=f"Special privileges assigned to '{user}'",
                        description="Windows Event 4672: admin-equivalent privileges granted at logon.",
                        source_ip=ev.source_ip,
                        user=user,
                        timestamp=ev.timestamp,
                        event_count=1,
                        evidence=[ev.raw[:200]],
                        mitre_tactic="Privilege Escalation",
                        mitre_id="T1078",
                    ))

        # ── Windows privileged group membership change ────────────────────
        elif ev.action == "group_member_add":
            user  = ev.user or "unknown"
            group = ev.extra.get("GroupName", ev.extra.get("TargetSid", ""))
            if any(pg.lower() in group.lower() for pg in _PRIV_GROUPS):
                key = f"group_add_{user}_{group}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="PrivEsc",
                        severity=Severity.CRITICAL,
                        title=f"User added to privileged group: {group}",
                        description=(
                            f"'{user}' was added to '{group}'. "
                            f"This grants elevated Windows privileges immediately."
                        ),
                        source_ip=ev.source_ip,
                        user=user,
                        timestamp=ev.timestamp,
                        event_count=1,
                        evidence=[ev.raw[:200]],
                        mitre_tactic="Privilege Escalation",
                        mitre_id="T1098",
                    ))

        # ── Scheduled task / service installation (persistence vector) ────
        elif ev.action in ("scheduled_task", "service_installed"):
            eid   = ev.extra.get("event_id", 0)
            label = "Scheduled task created" if ev.action == "scheduled_task" else "New service installed"
            key   = f"persist_{ev.user}_{ev.timestamp.isoformat()}"
            if key not in self._emitted:
                self._emitted.add(key)
                results.append(Alert(
                    alert_id=str(uuid.uuid4())[:8],
                    detector="PrivEsc",
                    severity=Severity.HIGH,
                    title=f"{label} by '{ev.user}'",
                    description=f"Windows Event {eid}: potential persistence mechanism established.",
                    source_ip=ev.source_ip,
                    user=ev.user,
                    timestamp=ev.timestamp,
                    event_count=1,
                    evidence=[ev.raw[:200]],
                    mitre_tactic="Persistence",
                    mitre_id="T1053.005" if ev.action == "scheduled_task" else "T1543.003",
                ))

        return results
