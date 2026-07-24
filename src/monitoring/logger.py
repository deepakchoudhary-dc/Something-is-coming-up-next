"""
Monitoring and Logging Module - Connected to SQLite database
"""

import contextvars
import logging
import logging.handlers
import re
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
from elasticsearch import Elasticsearch
from ..config.settings import settings
from ..monitoring.database import SessionLocal, SecurityLog

logger = logging.getLogger(__name__)

# ── Request ID context ─────────────────────────────────────────────────
_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set the request ID for the current async context.  Returns the ID."""
    rid = request_id or uuid.uuid4().hex[:16]
    _request_id_var.set(rid)
    return rid


def get_request_id() -> str:
    """Get the current request ID."""
    return _request_id_var.get("")

SENSITIVE_KEY_PATTERN = re.compile(r"(key|token|secret|password|credential|authorization|cookie)", re.IGNORECASE)
SECRET_VALUE_PATTERNS = [
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"), "[REDACTED OPENAI KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}"), "Authorization: Bearer [REDACTED]"),
    (re.compile(r"(?i)(?:api_key|apikey|password|secret|private_key|token|passwd|db_password)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?"), "[REDACTED CREDENTIAL]"),
]


def redact_for_log(value: Any, max_string: int = 500) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_for_log(item, max_string=max_string)
        return redacted
    if isinstance(value, list):
        return [redact_for_log(item, max_string=max_string) for item in value[:50]]
    if isinstance(value, str):
        result = value
        for pattern, replacement in SECRET_VALUE_PATTERNS:
            result = pattern.sub(replacement, result)
        if len(result) > max_string:
            return result[:max_string] + "...[TRUNCATED]"
        return result
    return value

class SecurityLogger:
    def __init__(self):
        self.es_client = None
        if settings.ELASTICSEARCH_HOST:
            try:
                self.es_client = Elasticsearch(
                    hosts=[{"host": settings.ELASTICSEARCH_HOST, "port": settings.ELASTICSEARCH_PORT}]
                )
            except Exception as e:
                logger.warning(f"Could not connect to Elasticsearch: {e}")

    def log_request(self, data: Dict[str, Any], log_type: str = "request"):
        """Log a generic request to console and elasticsearch (if configured)"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": log_type,
            "data": redact_for_log(data),
            "source": "ai_security_gateway"
        }
        logger.info(f"Security Log - {log_type}: {json.dumps(log_entry)}")
        if self.es_client:
            try:
                self.es_client.index(index="ai-security-logs", document=log_entry)
            except Exception as e:
                logger.error(f"Failed to log to Elasticsearch: {e}")

    def log_transaction(
        self,
        user_id: str,
        prompt: str,
        response: Optional[str],
        risk_score: float,
        flagged: bool,
        duration: float,
        anomalies: List[Dict],
        action_taken: str,
        client_ip: Optional[str] = "127.0.0.1",
        system_prompt: Optional[str] = None,
        retrieved_context: Optional[str] = None,
        trace: Optional[List[Dict]] = None,
        tenant_id: Optional[str] = None
    ):
        """
        Log a complete security transaction to the SQLite database
        """
        # Console output
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": get_request_id(),
            "user_id": user_id,
            "tenant_id": tenant_id,
            "prompt_len": len(prompt),
            "response_len": len(response) if response else 0,
            "risk_score": risk_score,
            "flagged": flagged,
            "duration": duration,
            "anomalies": redact_for_log(anomalies),
            "trace_steps": len(trace) if trace else 0,
            "action_taken": action_taken
        }
        logger.info(f"Gateway Transaction: {json.dumps(log_entry)}")

        # SQLite write
        session = SessionLocal()
        try:
            db_log = SecurityLog(
                user_id=user_id,
                prompt=prompt,
                system_prompt=system_prompt,
                retrieved_context=retrieved_context,
                response=response,
                risk_score=risk_score,
                flagged=flagged,
                duration=duration,
                anomalies=json.dumps(anomalies),
                trace_json=json.dumps(trace or []),
                action_taken=action_taken,
                client_ip=client_ip,
                request_id=get_request_id() or None,
                tenant_id=tenant_id,
                timestamp=datetime.utcnow()
            )
            session.add(db_log)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to write transaction to SQLite: {e}")
        finally:
            session.close()

    def log_anomaly(self, anomaly_data: Dict[str, Any]):
        """Log detected anomalies (console + optional ES)"""
        anomaly_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "anomaly",
            "anomaly": redact_for_log(anomaly_data),
            "severity": anomaly_data.get("severity", "medium")
        }
        logger.warning(f"Anomaly Detected: {json.dumps(anomaly_entry)}")

        if self.es_client:
            try:
                self.es_client.index(index="ai-security-anomalies", document=anomaly_entry)
            except Exception as e:
                logger.error(f"Failed to log anomaly to Elasticsearch: {e}")

    def log_security_event(self, event_data: Dict[str, Any]):
        """Log security-related events (console + optional ES)"""
        event_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "security_event",
            "event": redact_for_log(event_data)
        }
        logger.error(f"Security Event: {json.dumps(event_entry)}")

        if self.es_client:
            try:
                self.es_client.index(index="ai-security-events", document=event_entry)
            except Exception as e:
                logger.error(f"Failed to log security event to Elasticsearch: {e}")

class AnomalyDetector:
    def __init__(self):
        self.baseline_metrics = {
            "avg_request_length": 150,
            "avg_processing_time": 0.5,
            "normal_patterns": []
        }

    def detect_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in requests based on sizes, processing speeds, or repetitive words
        """
        anomalies = []
        severity = "low"

        # Check request length
        prompt = request_data.get("prompt", "")
        if prompt:
            length = len(prompt)
            if length > self.baseline_metrics["avg_request_length"] * 3:
                anomalies.append({
                    "type": "unusual_length",
                    "value": length,
                    "threshold": self.baseline_metrics["avg_request_length"] * 3,
                    "description": f"Prompt length ({length}) exceeds normal threshold"
                })
                severity = "medium"

        # Check for unusual patterns or characters (e.g. repeated characters indicative of token smash)
        if prompt:
            prompt_lower = prompt.lower()
            suspicious_patterns = ["repeat", "loop", "infinite", "bomb", "ignore previous"]
            for pattern in suspicious_patterns:
                if pattern in prompt_lower:
                    anomalies.append({
                        "type": "suspicious_pattern",
                        "pattern": pattern,
                        "description": f"Prompt contains suspicious keyword pattern: '{pattern}'"
                    })
                    severity = "high"

        return {
            "anomalies": anomalies,
            "severity": severity,
            "detected": len(anomalies) > 0
        }

# Global instances
security_logger = SecurityLogger()
anomaly_detector = AnomalyDetector()

class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON log formatter with request ID injection."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging():
    """Setup logging configuration with optional structured JSON format."""
    import os
    os.makedirs("logs", exist_ok=True)
    log_level = getattr(logging, settings.normalized_log_level())

    log_format = getattr(settings, "LOG_FORMAT", "text")

    if log_format == "json":
        formatter = StructuredJsonFormatter()
    else:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.handlers.RotatingFileHandler(
        "logs/ai_security.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, stream_handler],
    )
    logging.getLogger("watchfiles").setLevel(logging.WARNING)

def log_request(data: Dict[str, Any], log_type: str = "request"):
    """Convenience function to log requests"""
    security_logger.log_request(data, log_type)

def log_transaction(
    user_id: str,
    prompt: str,
    response: Optional[str],
    risk_score: float,
    flagged: bool,
    duration: float,
    anomalies: List[Dict],
    action_taken: str,
    client_ip: Optional[str] = "127.0.0.1",
    system_prompt: Optional[str] = None,
    retrieved_context: Optional[str] = None,
    trace: Optional[List[Dict]] = None,
    tenant_id: Optional[str] = None
):
    """Convenience function to log a complete transaction"""
    security_logger.log_transaction(
        user_id, prompt, response, risk_score, flagged, duration, anomalies, action_taken, client_ip, system_prompt, retrieved_context, trace, tenant_id
    )

def log_anomaly(anomaly_data: Dict[str, Any]):
    """Convenience function to log anomalies"""
    security_logger.log_anomaly(anomaly_data)

def detect_anomaly(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to detect anomalies"""
    return anomaly_detector.detect_anomaly(request_data)
