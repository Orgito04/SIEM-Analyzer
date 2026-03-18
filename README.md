SIEM Log Analyzer
A professional-grade Security Information and Event Management tool built in Python. Parses multiple log formats, runs multi-layered detection logic, and delivers results through both a rich terminal CLI and a web dashboard.

Features
Log Sources
Source	Formats Supported
Linux auth	auth.log, syslog, /var/log/secure
Web servers	Apache/Nginx combined log, Nginx error log
Windows	Exported XML (wevtutil), JSON (Get-WinEvent), plain text
Custom	NDJSON, JSON arrays — auto-mapped field names
Detection Engines
Brute Force Detector

SSH login failures with sliding time windows
Web login hammering (POST flood)
Password spray (one IP → many users) — MITRE T1110.003
Distributed brute force (many IPs → one user) — MITRE T1110.004
Privilege Escalation Detector

Dangerous sudo commands (/bin/bash, nmap, /etc/shadow, etc.)
su to root tracking
High-frequency sudo usage
Windows: Event 4672 (special privileges), 4728/4732/4756 (group adds)
Scheduled task creation and service installation (persistence)
Anomaly Engine

New source IP for known user (behavioral deviation)
Off-hours login detection (configurable business hours)
Web path scanning (distinct endpoint enumeration)
High error rate from single IP
User-agent rotation (tool fingerprint evasion)
Statistical volume spike detection (z-score baseline)
SQL injection / path traversal pattern matching
Alert System
4-tier severity: LOW / MEDIUM / HIGH / CRITICAL
MITRE ATT&CK tactic and technique tags on every alert
Deduplication (no repeated alerts for same event)
Alert scoring for attacker ranking
CSV and JSON export
Slack webhook and email (SMTP) notification
Installation
git clone https://github.com/yourname/siem-analyzer
cd siem-analyzer
pip install -r requirements.txt
Requirements: Python 3.10+ · Flask (for web UI only)

Usage
Generate sample logs (for testing)
python generate_samples.py
CLI — analyze log files
# Auto-detect file type
python cli.py auth.log access.log events.json

# Force parser type
python cli.py security.log --parser windows

# Filter to high severity only
python cli.py auth.log --min-severity HIGH

# Export to specific directory
python cli.py auth.log --output-dir /tmp/siem_reports

# Send Slack notification after analysis
python cli.py auth.log --slack-webhook https://hooks.slack.com/...

# Launch web dashboard after CLI analysis
python cli.py auth.log --web --port 8080
Web Dashboard
python app.py --port 5000
# → open http://localhost:5000
Drag and drop log files onto the browser, click Analyze, view results in real-time.

Project Structure
siem/
├── cli.py                  # Terminal interface
├── app.py                  # Flask web dashboard
├── generate_samples.py     # Test log generator
├── requirements.txt
│
├── core/
│   ├── models.py           # LogEvent, Alert, Severity
│   ├── engine.py           # Orchestrator (parser → detector → manager)
│   └── alert_manager.py    # Dedup, export, notifications
│
├── parsers/
│   ├── auth_parser.py      # Linux auth.log / syslog
│   ├── web_parser.py       # Apache / Nginx
│   ├── windows_parser.py   # Windows Event Logs
│   └── json_parser.py      # Generic JSON / NDJSON
│
├── detectors/
│   ├── brute_force.py      # Brute force + spray + distributed
│   ├── privesc.py          # Privilege escalation
│   └── anomaly.py          # Statistical + behavioral anomalies
│
├── templates/
│   └── index.html          # Web dashboard UI
│
├── sample_logs/            # Generated test logs
└── reports/                # Exported JSON/CSV reports
MITRE ATT&CK Coverage
Tactic	Technique	Detector
Credential Access	T1110.001 — Password Brute Force	BruteForce
Credential Access	T1110.003 — Password Spraying	BruteForce
Credential Access	T1110.004 — Credential Stuffing	BruteForce
Privilege Escalation	T1548.003 — Sudo and Sudo Caching	PrivEsc
Privilege Escalation	T1548 — Abuse Elevation Control	PrivEsc
Privilege Escalation	T1098 — Account Manipulation	PrivEsc
Initial Access	T1078 — Valid Accounts	Anomaly
Initial Access	T1190 — Exploit Public-Facing App	Anomaly
Discovery	T1595.003 — Wordlist Scanning	Anomaly
Discovery	T1595 — Active Scanning	Anomaly
Defense Evasion	T1036 — Masquerading	Anomaly
Persistence	T1053.005 — Scheduled Task	PrivEsc
Persistence	T1543.003 — Windows Service	PrivEsc
Extending the Tool
Add a new detector:

# detectors/my_detector.py
from core.models import LogEvent, Alert, Severity

class MyDetector:
    def feed(self, events: list[LogEvent]) -> list[Alert]:
        alerts = []
        for ev in events:
            # your logic here
            pass
        return alerts
Then register it in core/engine.py.

Add a new log parser:

# parsers/my_parser.py
from core.models import LogEvent
from typing import Iterator

def parse_my_log(path: str) -> Iterator[LogEvent]:
    with open(path) as fh:
        for line in fh:
            yield LogEvent(...)
License
MIT

