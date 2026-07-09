"""
In-process metrics collector for the AI Security Gateway.

Provides thread-safe counters and gauges, plus a Prometheus-compatible
text exposition endpoint.  Alerting thresholds are checked inline.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..config.settings import settings

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Thread-safe counters and gauges with optional alert thresholds."""

    def __init__(self):
        self._lock = threading.RLock()
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._alerts: List[Dict[str, Any]] = []
        self._start_time = time.monotonic()

    # ── Counter operations ────────────────────────────────────────
    def inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += value
        self._check_alert(name, self._counters[key])

    def get_counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        return self._counters.get(self._key(name, labels), 0.0)

    # ── Gauge operations ──────────────────────────────────────────
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def get_gauge(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        return self._gauges.get(self._key(name, labels), 0.0)

    # ── Histogram operations ──────────────────────────────────────
    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._histograms[key].append(value)
            # Keep bounded
            if len(self._histograms[key]) > 10000:
                self._histograms[key] = self._histograms[key][-5000:]

    # ── Alerting ──────────────────────────────────────────────────
    def _check_alert(self, name: str, value: float) -> None:
        """Check alerting thresholds for specific metrics."""
        total = self._counters.get("requests_total", 0)
        if total < 10:
            return

        block_threshold = float(getattr(settings, "ALERT_BLOCK_RATE_THRESHOLD", 0.5))
        failover_threshold = float(getattr(settings, "ALERT_FAILOVER_RATE_THRESHOLD", 0.3))

        if name == "requests_blocked":
            rate = self._counters.get("requests_blocked", 0) / total
            if rate > block_threshold:
                self._emit_alert("high_block_rate", f"Block rate {rate:.2%} exceeds threshold {block_threshold:.2%}")

        if name == "requests_failover":
            rate = self._counters.get("requests_failover", 0) / total
            if rate > failover_threshold:
                self._emit_alert("high_failover_rate", f"Failover rate {rate:.2%} exceeds threshold {failover_threshold:.2%}")

    def _emit_alert(self, alert_type: str, message: str) -> None:
        alert = {
            "type": alert_type,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
        with self._lock:
            # Deduplicate within the last 60 seconds
            recent = [a for a in self._alerts if a["type"] == alert_type
                      and (datetime.utcnow() - datetime.fromisoformat(a["timestamp"])).total_seconds() < 60]
            if not recent:
                self._alerts.append(alert)
                logger.warning("ALERT [%s]: %s", alert_type, message)

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self._alerts[-limit:]))

    # ── Exposition ────────────────────────────────────────────────
    def to_prometheus(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        lines = []
        with self._lock:
            for key, value in sorted(self._counters.items()):
                metric_name = key.replace("{", "_").replace("}", "").replace(",", "_").replace("=", "_")
                lines.append(f"# TYPE {metric_name} counter")
                lines.append(f"{metric_name} {value}")

            for key, value in sorted(self._gauges.items()):
                metric_name = key.replace("{", "_").replace("}", "").replace(",", "_").replace("=", "_")
                lines.append(f"# TYPE {metric_name} gauge")
                lines.append(f"{metric_name} {value}")

            for key, values in sorted(self._histograms.items()):
                if not values:
                    continue
                metric_name = key.replace("{", "_").replace("}", "").replace(",", "_").replace("=", "_")
                count = len(values)
                total = sum(values)
                lines.append(f"# TYPE {metric_name} summary")
                lines.append(f"{metric_name}_count {count}")
                lines.append(f"{metric_name}_sum {total:.6f}")

        lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable snapshot."""
        with self._lock:
            total = self._counters.get("requests_total", 0)
            blocked = self._counters.get("requests_blocked", 0)
            redacted = self._counters.get("requests_redacted", 0)
            hitl = self._counters.get("requests_hitl", 0)
            failover = self._counters.get("requests_failover", 0)
            allowed = self._counters.get("requests_allowed", 0)

            durations = self._histograms.get("request_duration_seconds", [])
            avg_duration = sum(durations) / len(durations) if durations else 0.0

            return {
                "requests_total": total,
                "requests_allowed": allowed,
                "requests_blocked": blocked,
                "requests_redacted": redacted,
                "requests_hitl": hitl,
                "requests_failover": failover,
                "block_rate": (blocked / total) if total > 0 else 0.0,
                "failover_rate": (failover / total) if total > 0 else 0.0,
                "avg_duration_seconds": round(avg_duration, 6),
                "active_hitl_pending": self._gauges.get("active_hitl_pending", 0),
                "uptime_seconds": round(time.monotonic() - self._start_time, 1),
                "alerts": self.get_alerts(10),
            }

    @staticmethod
    def _key(name: str, labels: Optional[Dict[str, str]] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


# ── Module-level singleton ─────────────────────────────────────────────
_collector: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector
