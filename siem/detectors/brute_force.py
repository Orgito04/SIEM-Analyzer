"""
Brute Force Detector
Detects: SSH brute force, web login hammering, password spray attacks,
         credential stuffing (many users from one IP), distributed brute force.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterator
from core.models import LogEvent, Alert, Severity

# Tunable thresholds
BRUTE_WINDOW_SECONDS  = 300   # 5-minute sliding window
SSH_FAIL_THRESHOLD    = 5     # failures before LOW alert
SSH_FAIL_HIGH         = 20    # failures before HIGH alert
SSH_FAIL_CRITICAL     = 50    # failures before CRITICAL
WEB_FAIL_THRESHOLD    = 10
WEB_FAIL_HIGH         = 40
SPRAY_USER_THRESHOLD  = 5     # # distinct users from one IP → spray
DISTRIB_IP_THRESHOLD  = 8     # # distinct IPs hitting same user → distributed


class BruteForceDetector:
    """
    Stateful detector: feed events one-by-one, pull alerts after each batch.
    Uses time-windowed buckets to avoid memory bloat on large log files.
    """

    def __init__(self,
                 window_seconds: int = BRUTE_WINDOW_SECONDS,
                 ssh_threshold: int  = SSH_FAIL_THRESHOLD,
                 web_threshold: int  = WEB_FAIL_THRESHOLD):
        self.window   = timedelta(seconds=window_seconds)
        self.ssh_thr  = ssh_threshold
        self.web_thr  = web_threshold

        # ip -> list of (timestamp, user) for failures
        self._ssh_fails:  defaultdict[str, list] = defaultdict(list)
        self._web_fails:  defaultdict[str, list] = defaultdict(list)

        # user -> set of source IPs (distributed detection)
        self._user_ips:   defaultdict[str, set]  = defaultdict(set)

        # ip -> set of usernames tried (password spray)
        self._ip_users:   defaultdict[str, set]  = defaultdict(set)

        self._emitted: set = set()   # deduplicate alert keys

    def _prune(self, bucket: list, before: datetime) -> list:
        return [(ts, u) for ts, u in bucket if ts >= before]

    def feed(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for ev in events:
            if ev.status not in ("failure", "forbidden"):
                continue

            cutoff = ev.timestamp - self.window

            # --- SSH / auth failures ---
            if ev.action in ("ssh_login", "ssh_invalid_user", "pam_auth_fail",
                              "sudo_fail", "su_fail", "logon_failure", "kerberos_preauth"):
                ip   = ev.source_ip or "unknown"
                user = ev.user or "unknown"

                self._ssh_fails[ip] = self._prune(self._ssh_fails[ip], cutoff)
                self._ssh_fails[ip].append((ev.timestamp, user))

                if ev.user:
                    self._user_ips[user].add(ip)
                if ip != "unknown":
                    self._ip_users[ip].add(user)

                count = len(self._ssh_fails[ip])

                # Threshold-based severity
                if count >= SSH_FAIL_CRITICAL:
                    sev = Severity.CRITICAL
                elif count >= SSH_FAIL_HIGH:
                    sev = Severity.HIGH
                elif count >= self.ssh_thr:
                    sev = Severity.MEDIUM
                else:
                    sev = None

                if sev and count % 5 == 0:   # alert every 5 new hits above threshold
                    key = f"brute_ssh_{ip}_{count // 5}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        users_tried = list({u for _, u in self._ssh_fails[ip]})
                        alerts.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="BruteForce",
                            severity=sev,
                            title=f"SSH brute force from {ip}",
                            description=(
                                f"{count} failed auth attempts in {self.window.seconds // 60} min "
                                f"targeting {len(users_tried)} user(s)."
                            ),
                            source_ip=ip,
                            user=users_tried[0] if len(users_tried) == 1 else None,
                            timestamp=ev.timestamp,
                            event_count=count,
                            evidence=[raw for _, raw in self._ssh_fails[ip][-5:]],
                            mitre_tactic="Credential Access",
                            mitre_id="T1110.001",
                        ))

                # Password spray: one IP → many users
                if len(self._ip_users[ip]) >= SPRAY_USER_THRESHOLD:
                    key = f"spray_{ip}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        alerts.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="BruteForce",
                            severity=Severity.HIGH,
                            title=f"Password spray from {ip}",
                            description=(
                                f"Single IP targeting {len(self._ip_users[ip])} distinct users — "
                                f"pattern consistent with password spray attack."
                            ),
                            source_ip=ip,
                            user=None,
                            timestamp=ev.timestamp,
                            event_count=len(self._ip_users[ip]),
                            evidence=list(self._ip_users[ip])[:5],
                            mitre_tactic="Credential Access",
                            mitre_id="T1110.003",
                        ))

            # --- Web login failures ---
            elif ev.action in ("http_post",) and ev.log_type == "web":
                ip = ev.source_ip or "unknown"
                self._web_fails[ip] = self._prune(self._web_fails[ip], cutoff)
                self._web_fails[ip].append((ev.timestamp, ev.extra.get("path", "")))

                count = len(self._web_fails[ip])
                if count >= WEB_FAIL_HIGH:
                    sev = Severity.HIGH
                elif count >= self.web_thr:
                    sev = Severity.MEDIUM
                else:
                    sev = None

                if sev and count % 10 == 0:
                    key = f"brute_web_{ip}_{count // 10}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        alerts.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="BruteForce",
                            severity=sev,
                            title=f"Web login brute force from {ip}",
                            description=f"{count} failed POST requests in {self.window.seconds // 60} min.",
                            source_ip=ip,
                            user=None,
                            timestamp=ev.timestamp,
                            event_count=count,
                            evidence=[p for _, p in self._web_fails[ip][-5:]],
                            mitre_tactic="Credential Access",
                            mitre_id="T1110.001",
                        ))

        # --- Distributed brute force: many IPs → same user ---
        for user, ips in self._user_ips.items():
            if len(ips) >= DISTRIB_IP_THRESHOLD:
                key = f"distrib_{user}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    alerts.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="BruteForce",
                        severity=Severity.HIGH,
                        title=f"Distributed brute force on user '{user}'",
                        description=(
                            f"{len(ips)} distinct IPs targeting the same account — "
                            f"likely botnet or distributed credential attack."
                        ),
                        source_ip=None,
                        user=user,
                        timestamp=datetime.now(),
                        event_count=len(ips),
                        evidence=list(ips)[:5],
                        mitre_tactic="Credential Access",
                        mitre_id="T1110.004",
                    ))

        return alerts
