"""
Anomaly / Outlier Detection Engine
Uses statistical baselines (mean + std dev) to detect:
  - Login time anomalies (off-hours access)
  - IP geolocation shifts (new IPs for known users)
  - Request volume spikes (web traffic bursts)
  - User behavior deviations (unusual action patterns)
  - Rare/new user agents
  - Scanning behavior (many distinct paths from one IP)
"""

import uuid
import math
from collections import defaultdict
from datetime import datetime, time
from typing import Iterator
from core.models import LogEvent, Alert, Severity

# Business hours: 07:00 – 20:00 local time
BUSINESS_START = time(7, 0)
BUSINESS_END   = time(20, 0)

# Web scanning thresholds
DISTINCT_PATH_THRESHOLD  = 30   # unique paths from one IP in session → scanner
DISTINCT_PATH_CRITICAL   = 80
ERROR_RATE_THRESHOLD     = 0.6  # >60% error responses → suspicious
REQUEST_SPIKE_MULTIPLIER = 3.0  # 3× baseline request rate → spike

# Statistical outlier: z-score threshold
Z_THRESHOLD = 2.5


def _z_score(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return abs(value - mean) / std


def _is_off_hours(ts: datetime) -> bool:
    t = ts.time()
    return not (BUSINESS_START <= t <= BUSINESS_END)


def _running_stats(values: list[float]) -> tuple[float, float]:
    """Return (mean, std_dev) for a list of floats."""
    if not values:
        return 0.0, 0.0
    n   = len(values)
    mu  = sum(values) / n
    var = sum((x - mu) ** 2 for x in values) / n
    return mu, math.sqrt(var)


class AnomalyDetector:

    def __init__(self):
        # Per-user known IPs
        self._user_known_ips:  defaultdict[str, set]   = defaultdict(set)
        # Per-user login hours (0-23)
        self._user_hours:      defaultdict[str, list]  = defaultdict(list)
        # Per-IP distinct paths (web scanning)
        self._ip_paths:        defaultdict[str, set]   = defaultdict(set)
        # Per-IP request counts per hour bucket
        self._ip_req_counts:   defaultdict[str, list]  = defaultdict(list)
        self._ip_req_errors:   defaultdict[str, list]  = defaultdict(list)
        # Per-IP user-agents
        self._ip_agents:       defaultdict[str, set]   = defaultdict(set)
        # Per-user action counts
        self._user_actions:    defaultdict[str, defaultdict] = defaultdict(lambda: defaultdict(int))
        # Track off-hours alerts per user per day
        self._offhours_alerted: set = set()
        self._emitted: set = set()

    def feed(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for ev in events:
            alerts.extend(self._process(ev))

        # After full batch: run volume spike analysis
        alerts.extend(self._check_volume_spikes())

        return alerts

    def _process(self, ev: LogEvent) -> list[Alert]:
        results = []
        user = ev.user or ""
        ip   = ev.source_ip or ""
        ts   = ev.timestamp

        # ── Track user baseline ────────────────────────────────────────
        if user:
            self._user_actions[user][ev.action] += 1

            if ev.status == "success" and ev.action in (
                "ssh_login", "logon_success", "http_get", "http_post"
            ):
                # New IP for known user
                if ip and len(self._user_known_ips[user]) >= 3 and ip not in self._user_known_ips[user]:
                    key = f"newip_{user}_{ip}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        results.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="Anomaly",
                            severity=Severity.MEDIUM,
                            title=f"New source IP for user '{user}'",
                            description=(
                                f"'{user}' logged in from {ip}, which has not been seen before. "
                                f"Known IPs: {len(self._user_known_ips[user])}."
                            ),
                            source_ip=ip,
                            user=user,
                            timestamp=ts,
                            event_count=1,
                            evidence=[ev.raw[:200]],
                            mitre_tactic="Initial Access",
                            mitre_id="T1078",
                        ))

                if ip:
                    self._user_known_ips[user].add(ip)

                # Off-hours login
                if _is_off_hours(ts):
                    key = f"offhours_{user}_{ts.date()}"
                    if key not in self._offhours_alerted:
                        self._offhours_alerted.add(key)
                        results.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="Anomaly",
                            severity=Severity.LOW,
                            title=f"Off-hours login by '{user}'",
                            description=(
                                f"Successful login at {ts.strftime('%H:%M')} "
                                f"(outside {BUSINESS_START.strftime('%H:%M')}–{BUSINESS_END.strftime('%H:%M')})."
                            ),
                            source_ip=ip,
                            user=user,
                            timestamp=ts,
                            event_count=1,
                            evidence=[ev.raw[:200]],
                            mitre_tactic="Initial Access",
                            mitre_id="T1078",
                        ))

                # Login hour tracking for behavioral baseline
                self._user_hours[user].append(ts.hour)

        # ── Web path scanning ──────────────────────────────────────────
        if ev.log_type == "web" and ip:
            path = ev.extra.get("path", "")
            ua   = ev.extra.get("user_agent", "")
            self._ip_paths[ip].add(path)
            self._ip_req_counts[ip].append(1)
            self._ip_agents[ip].add(ua)

            if ev.status in ("failure", "not_found", "forbidden"):
                self._ip_req_errors[ip].append(1)

            distinct = len(self._ip_paths[ip])

            if distinct >= DISTINCT_PATH_CRITICAL:
                sev = Severity.CRITICAL
            elif distinct >= DISTINCT_PATH_THRESHOLD:
                sev = Severity.HIGH
            else:
                sev = None

            if sev and distinct % 10 == 0:
                key = f"scan_{ip}_{distinct}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    # Error rate
                    total  = len(self._ip_req_counts[ip])
                    errors = len(self._ip_req_errors[ip])
                    err_rate = errors / total if total else 0

                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="Anomaly",
                        severity=sev,
                        title=f"Web scanning detected from {ip}",
                        description=(
                            f"{ip} has requested {distinct} distinct paths "
                            f"(error rate: {err_rate:.0%}). Consistent with automated scanning."
                        ),
                        source_ip=ip,
                        user=None,
                        timestamp=ts,
                        event_count=distinct,
                        evidence=list(self._ip_paths[ip])[-5:],
                        mitre_tactic="Discovery",
                        mitre_id="T1595.003",
                    ))

            # High error rate from single IP
            total  = len(self._ip_req_counts[ip])
            errors = len(self._ip_req_errors[ip])
            if total >= 20:
                err_rate = errors / total
                if err_rate >= ERROR_RATE_THRESHOLD:
                    key = f"errrate_{ip}"
                    if key not in self._emitted:
                        self._emitted.add(key)
                        results.append(Alert(
                            alert_id=str(uuid.uuid4())[:8],
                            detector="Anomaly",
                            severity=Severity.MEDIUM,
                            title=f"High error rate from {ip}",
                            description=f"{err_rate:.0%} of requests from {ip} returned errors ({errors}/{total}).",
                            source_ip=ip,
                            user=None,
                            timestamp=ts,
                            event_count=total,
                            evidence=[],
                            mitre_tactic="Discovery",
                            mitre_id="T1595",
                        ))

            # Multiple user-agents from same IP (bot / tool rotation)
            if len(self._ip_agents[ip]) >= 5:
                key = f"multiua_{ip}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="Anomaly",
                        severity=Severity.MEDIUM,
                        title=f"Multiple user-agents from {ip}",
                        description=(
                            f"{len(self._ip_agents[ip])} distinct user-agents from single IP — "
                            f"possible tool rotation or bot activity."
                        ),
                        source_ip=ip,
                        user=None,
                        timestamp=ts,
                        event_count=len(self._ip_agents[ip]),
                        evidence=list(self._ip_agents[ip])[:5],
                        mitre_tactic="Defense Evasion",
                        mitre_id="T1036",
                    ))

            # Suspicious path content
            if ev.extra.get("suspicious"):
                key = f"susppath_{ip}_{path[:40]}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    results.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="Anomaly",
                        severity=Severity.HIGH,
                        title=f"Suspicious path requested by {ip}",
                        description=f"Request to '{path}' contains patterns associated with exploitation.",
                        source_ip=ip,
                        user=None,
                        timestamp=ts,
                        event_count=1,
                        evidence=[path, ua],
                        mitre_tactic="Initial Access",
                        mitre_id="T1190",
                    ))

        return results

    def _check_volume_spikes(self) -> list[Alert]:
        """After full batch, flag IPs with request volume >> baseline."""
        alerts = []
        counts = [len(v) for v in self._ip_req_counts.values() if len(v) > 5]
        if len(counts) < 3:
            return alerts

        mu, std = _running_stats(counts)

        for ip, reqs in self._ip_req_counts.items():
            n = len(reqs)
            z = _z_score(n, mu, std)
            if z >= Z_THRESHOLD and n > 50:
                key = f"spike_{ip}"
                if key not in self._emitted:
                    self._emitted.add(key)
                    alerts.append(Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        detector="Anomaly",
                        severity=Severity.HIGH if z > 4 else Severity.MEDIUM,
                        title=f"Request volume spike from {ip}",
                        description=(
                            f"{ip} made {n} requests (z-score: {z:.1f}×σ above mean {mu:.0f}). "
                            f"Significant outlier compared to other IPs."
                        ),
                        source_ip=ip,
                        user=None,
                        timestamp=datetime.now(),
                        event_count=n,
                        evidence=[],
                        mitre_tactic="Impact",
                        mitre_id="T1499",
                    ))
        return alerts
