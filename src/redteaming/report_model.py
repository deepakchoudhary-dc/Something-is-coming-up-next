"""
Red-team report storage model.

Stores scan results separately from user traffic SecurityLogs
to keep red-team data isolated for compliance.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from ..monitoring.database import Base


class RedTeamReport(Base):
    __tablename__ = "redteam_reports"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    payload_version = Column(String(50), default="1.0")
    scan_duration_seconds = Column(Float, default=0.0)
    total_payloads = Column(Integer, default=0)
    malicious_tested = Column(Integer, default=0)
    benign_tested = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    bypassed_count = Column(Integer, default=0)
    bypass_rate = Column(Float, default=0.0)
    security_posture = Column(String(50), default="unknown")
    results_json = Column(Text, default="[]")  # Full per-payload results
    metrics_json = Column(Text, default="{}")  # Summary metrics
