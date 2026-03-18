"""
Alert Manager
Handles: deduplication, severity scoring, timeline building,
         CSV/JSON export, Slack/email notification hooks.
"""

import csv
import json
import smtplib
import urllib.request
from datetime import datetime
from collections import defaultdict
from email.mime.text import MIMEText
from pathlib import Path
from core.models import Alert, Severity


class AlertManager:

    def __init__(self, output_dir: str = "reports"):
        self._alerts:    list[Alert] = []
        self._seen_ids:  set         = set()
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def ingest(self, alerts: list[Alert]) -> None:
        for a in alerts:
            if a.alert_id not in self._seen_ids:
                self._seen_ids.add(a.alert_id)
                self._alerts.append(a)

    @property
    def alerts(self) -> list[Alert]:
        return sorted(self._alerts, key=lambda a: (-a.severity.score, a.timestamp), reverse=False)

    def summary(self) -> dict:
        counts = defaultdict(int)
        detectors = defaultdict(int)
        ips: set = set()
        users: set = set()

        for a in self._alerts:
            counts[a.severity.label] += 1
            detectors[a.detector] += 1
            if a.source_ip:
                ips.add(a.source_ip)
            if a.user:
                users.add(a.user)

        return {
            "total":       len(self._alerts),
            "by_severity": dict(counts),
            "by_detector": dict(detectors),
            "unique_ips":  len(ips),
            "unique_users": len(users),
            "critical":    counts.get("CRITICAL", 0),
            "high":        counts.get("HIGH", 0),
            "medium":      counts.get("MEDIUM", 0),
            "low":         counts.get("LOW", 0),
        }

    def top_attackers(self, n: int = 10) -> list[dict]:
        ip_scores: defaultdict[str, int] = defaultdict(int)
        ip_alerts: defaultdict[str, list] = defaultdict(list)

        for a in self._alerts:
            if a.source_ip:
                ip_scores[a.source_ip] += a.severity.score
                ip_alerts[a.source_ip].append(a.severity.label)

        ranked = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)
        return [
            {"ip": ip, "score": score, "alerts": ip_alerts[ip]}
            for ip, score in ranked[:n]
        ]

    def timeline(self) -> list[dict]:
        """Group alerts by hour for timeline visualization."""
        buckets: defaultdict[str, list] = defaultdict(list)
        for a in sorted(self._alerts, key=lambda x: x.timestamp):
            hour = a.timestamp.strftime("%Y-%m-%d %H:00")
            buckets[hour].append(a.severity.label)

        return [
            {
                "hour":     hour,
                "total":    len(sevs),
                "critical": sevs.count("CRITICAL"),
                "high":     sevs.count("HIGH"),
                "medium":   sevs.count("MEDIUM"),
                "low":      sevs.count("LOW"),
            }
            for hour, sevs in sorted(buckets.items())
        ]

    def mitre_coverage(self) -> dict:
        """Which MITRE ATT&CK tactics were triggered."""
        tactics: defaultdict[str, int] = defaultdict(int)
        for a in self._alerts:
            if a.mitre_tactic:
                tactics[a.mitre_tactic] += 1
        return dict(sorted(tactics.items(), key=lambda x: x[1], reverse=True))

    def export_json(self, filename: str | None = None) -> Path:
        fname = filename or f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path  = self._output_dir / fname
        payload = {
            "generated_at": datetime.now().isoformat(),
            "summary":      self.summary(),
            "top_attackers": self.top_attackers(),
            "mitre_coverage": self.mitre_coverage(),
            "alerts":       [a.to_dict() for a in self.alerts],
        }
        path.write_text(json.dumps(payload, indent=2, default=str))
        return path

    def export_csv(self, filename: str | None = None) -> Path:
        fname = filename or f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path  = self._output_dir / fname
        fields = [
            "alert_id", "detector", "severity", "title",
            "source_ip", "user", "timestamp", "event_count",
            "mitre_tactic", "mitre_id", "description",
        ]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for a in self.alerts:
                row = a.to_dict()
                row["description"] = row["description"][:200]
                writer.writerow(row)
        return path

    def notify_slack(self, webhook_url: str) -> bool:
        """Send a summary to a Slack webhook URL."""
        s = self.summary()
        text = (
            f"*SIEM Alert Summary*\n"
            f"🔴 Critical: {s['critical']}  🟠 High: {s['high']}  "
            f"🟡 Medium: {s['medium']}  🔵 Low: {s['low']}\n"
            f"Total: {s['total']} alerts | {s['unique_ips']} IPs | {s['unique_users']} users"
        )
        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception:
            return False

    def notify_email(self, smtp_host: str, smtp_port: int,
                     sender: str, recipient: str,
                     username: str | None = None,
                     password: str | None = None) -> bool:
        """Send alert summary via email."""
        s = self.summary()
        body = (
            f"SIEM Analysis Report\n"
            f"Generated: {datetime.now().isoformat()}\n\n"
            f"CRITICAL: {s['critical']}\n"
            f"HIGH:     {s['high']}\n"
            f"MEDIUM:   {s['medium']}\n"
            f"LOW:      {s['low']}\n"
            f"Total:    {s['total']}\n\n"
            f"Top Attackers:\n"
        )
        for att in self.top_attackers(5):
            body += f"  {att['ip']} — score {att['score']}\n"

        msg = MIMEText(body)
        msg["Subject"] = f"[SIEM] {s['critical']} CRITICAL / {s['high']} HIGH alerts"
        msg["From"]    = sender
        msg["To"]      = recipient

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                if username and password:
                    server.login(username, password)
                server.sendmail(sender, recipient, msg.as_string())
            return True
        except Exception:
            return False
