"""
Core data models for the SIEM analyzer.
All log sources normalize into LogEvent. All detections produce Alert.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    LOW      = ("LOW",      "\033[94m",  "#3b82f6")   # blue
    MEDIUM   = ("MEDIUM",   "\033[93m",  "#f59e0b")   # amber
    HIGH     = ("HIGH",     "\033[91m",  "#ef4444")   # red
    CRITICAL = ("CRITICAL", "\033[95m",  "#dc2626")   # deep red

    def __init__(self, label, ansi, hex_color):
        self.label     = label
        self.ansi      = ansi
        self.hex_color = hex_color

    @property
    def score(self):
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.label]


@dataclass
class LogEvent:
    """Normalized representation of any log line."""
    timestamp:  datetime
    source_ip:  Optional[str]
    user:       Optional[str]
    action:     str
    status:     str                    # success / failure / unknown
    raw:        str
    log_type:   str                    # auth / web / windows / json
    extra:      dict = field(default_factory=dict)


@dataclass
class Alert:
    """A detection finding raised by any detector."""
    alert_id:    str
    detector:    str
    severity:    Severity
    title:       str
    description: str
    source_ip:   Optional[str]
    user:        Optional[str]
    timestamp:   datetime
    event_count: int
    evidence:    list[str] = field(default_factory=list)
    mitre_tactic: Optional[str] = None
    mitre_id:     Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "alert_id":     self.alert_id,
            "detector":     self.detector,
            "severity":     self.severity.label,
            "hex_color":    self.severity.hex_color,
            "title":        self.title,
            "description":  self.description,
            "source_ip":    self.source_ip,
            "user":         self.user,
            "timestamp":    self.timestamp.isoformat(),
            "event_count":  self.event_count,
            "evidence":     self.evidence[:5],
            "mitre_tactic": self.mitre_tactic,
            "mitre_id":     self.mitre_id,
        }
