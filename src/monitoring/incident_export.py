"""
Incident export for compliance and investigation workflows.

Exports security logs within a time range, with optional redaction of
sensitive fields (prompts, responses) for safe sharing.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..monitoring.database import SessionLocal, SecurityLog

logger = logging.getLogger(__name__)


def export_incident(
    start_time: datetime,
    end_time: datetime,
    include_prompts: bool = False,
    include_responses: bool = False,
    tenant_id: Optional[str] = None,
    max_records: int = 10000,
) -> Dict[str, Any]:
    """Export security logs within a time range for incident investigation.

    Args:
        start_time: Start of the export window (UTC).
        end_time: End of the export window (UTC).
        include_prompts: If False, prompts are redacted from the export.
        include_responses: If False, responses are redacted.
        tenant_id: Optional tenant filter.
        max_records: Cap on number of records.

    Returns:
        Dict with metadata and a ``records`` list.
    """
    session = SessionLocal()
    try:
        query = session.query(SecurityLog).filter(
            SecurityLog.timestamp >= start_time,
            SecurityLog.timestamp <= end_time,
        )
        if tenant_id:
            query = query.filter(SecurityLog.user_id.like(f"{tenant_id}:%"))

        logs = query.order_by(SecurityLog.timestamp.asc()).limit(max_records).all()

        records: List[Dict[str, Any]] = []
        for log in logs:
            record: Dict[str, Any] = {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user_id": log.user_id,
                "risk_score": log.risk_score,
                "flagged": log.flagged,
                "action_taken": log.action_taken,
                "duration": log.duration,
            }

            if include_prompts:
                record["prompt"] = log.prompt
                record["system_prompt"] = getattr(log, "system_prompt", None)
                record["retrieved_context"] = getattr(log, "retrieved_context", None)
            else:
                record["prompt"] = "[REDACTED]"
                record["system_prompt"] = "[REDACTED]"
                record["retrieved_context"] = "[REDACTED]"

            if include_responses:
                record["response"] = log.response
            else:
                record["response"] = "[REDACTED]"

            # Always include anomalies and trace (they don't contain raw user data)
            try:
                record["anomalies"] = json.loads(log.anomalies) if log.anomalies else []
            except Exception:
                record["anomalies"] = []
            try:
                record["trace"] = json.loads(log.trace_json) if getattr(log, "trace_json", None) else []
            except Exception:
                record["trace"] = []

            records.append(record)

        return {
            "export_metadata": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "record_count": len(records),
                "include_prompts": include_prompts,
                "include_responses": include_responses,
                "tenant_id": tenant_id,
                "exported_at": datetime.utcnow().isoformat(),
            },
            "records": records,
        }
    except Exception as exc:
        logger.error("Incident export failed: %s", exc, exc_info=True)
        raise
    finally:
        session.close()
