"""
Notification dispatch for HITL review events and system alerts.

Supports pluggable providers: SMTP email, webhook (HTTP POST), and log-only fallback.
Configuration is driven by settings: NOTIFICATION_PROVIDER, SMTP_*, WEBHOOK_URL.
"""

import abc
import json
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text

from ..config.settings import settings
from ..monitoring.database import Base, SessionLocal

logger = logging.getLogger(__name__)


# ── Notification Log Model ─────────────────────────────────────────────
class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    channel = Column(String(50), nullable=False)  # email, webhook, log
    recipient = Column(String(500), nullable=True)
    subject = Column(String(500), nullable=True)
    status = Column(String(50), default="sent")  # sent, failed
    error = Column(Text, nullable=True)
    payload_summary = Column(Text, nullable=True)


# ── Provider Interface ─────────────────────────────────────────────────
class NotificationProvider(abc.ABC):
    @abc.abstractmethod
    async def send(self, recipient: str, subject: str, body: str, metadata: Optional[Dict] = None) -> bool:
        """Send a notification. Return True on success."""


# ── Email Provider ─────────────────────────────────────────────────────
class EmailNotifier(NotificationProvider):
    """SMTP-based email delivery."""

    def __init__(self):
        self.host = getattr(settings, "SMTP_HOST", "")
        self.port = int(getattr(settings, "SMTP_PORT", 587))
        self.user = getattr(settings, "SMTP_USER", "")
        self.password = getattr(settings, "SMTP_PASSWORD", "")
        self.from_addr = getattr(settings, "SMTP_FROM", self.user or "noreply@ai-security-gateway.local")
        self.use_tls = getattr(settings, "SMTP_USE_TLS", True)

    async def send(self, recipient: str, subject: str, body: str, metadata: Optional[Dict] = None) -> bool:
        if not self.host:
            logger.error("SMTP_HOST not configured — email notification skipped")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.from_addr
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            if self.use_tls:
                server = smtplib.SMTP(self.host, self.port, timeout=10)
                server.ehlo()
                server.starttls()
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=10)
                server.ehlo()

            if self.user and self.password:
                server.login(self.user, self.password)

            server.sendmail(self.from_addr, [recipient], msg.as_string())
            server.quit()
            logger.info("Email notification sent to %s: %s", recipient, subject)
            return True
        except Exception as exc:
            logger.error("Email delivery failed to %s: %s", recipient, exc)
            return False


# ── Webhook Provider ───────────────────────────────────────────────────
class WebhookNotifier(NotificationProvider):
    """HTTP POST webhook delivery."""

    def __init__(self):
        self.url = getattr(settings, "WEBHOOK_URL", "")

    async def send(self, recipient: str, subject: str, body: str, metadata: Optional[Dict] = None) -> bool:
        if not self.url:
            logger.error("WEBHOOK_URL not configured — webhook notification skipped")
            return False
        try:
            import httpx
            payload = {
                "recipient": recipient,
                "subject": subject,
                "body": body,
                "timestamp": datetime.utcnow().isoformat(),
                **(metadata or {}),
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.url, json=payload)
                resp.raise_for_status()
            logger.info("Webhook notification sent to %s: %s", self.url, subject)
            return True
        except Exception as exc:
            logger.error("Webhook delivery failed to %s: %s", self.url, exc)
            return False


# ── Log-only Provider (fallback) ──────────────────────────────────────
class LogNotifier(NotificationProvider):
    """Logs the notification instead of delivering it externally."""

    async def send(self, recipient: str, subject: str, body: str, metadata: Optional[Dict] = None) -> bool:
        logger.info(
            "[NOTIFICATION LOG] to=%s subject=%s body_length=%d",
            recipient, subject, len(body),
        )
        return True


# ── Dispatcher ─────────────────────────────────────────────────────────
class NotificationDispatcher:
    """Routes notifications to the configured provider and logs the result."""

    def __init__(self):
        provider_name = getattr(settings, "NOTIFICATION_PROVIDER", "log")
        self._providers: Dict[str, NotificationProvider] = {
            "log": LogNotifier(),
        }
        # Initialise real providers only when configured
        if getattr(settings, "SMTP_HOST", ""):
            self._providers["email"] = EmailNotifier()
        if getattr(settings, "WEBHOOK_URL", ""):
            self._providers["webhook"] = WebhookNotifier()

        self._default_provider = provider_name
        if self._default_provider not in self._providers:
            logger.warning("Configured NOTIFICATION_PROVIDER=%s not available, falling back to log",
                           self._default_provider)
            self._default_provider = "log"

    async def send(
        self,
        recipient: str,
        subject: str,
        body: str,
        channel: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> bool:
        """Send a notification via the specified (or default) channel."""
        ch = channel or self._default_provider
        provider = self._providers.get(ch)
        if not provider:
            logger.error("Notification channel %s not available", ch)
            provider = self._providers["log"]
            ch = "log"

        success = await provider.send(recipient, subject, body, metadata)
        self._log_notification(ch, recipient, subject, success)
        return success

    def _log_notification(self, channel: str, recipient: str, subject: str, success: bool) -> None:
        session = SessionLocal()
        try:
            log_entry = NotificationLog(
                channel=channel,
                recipient=recipient,
                subject=subject,
                status="sent" if success else "failed",
                timestamp=datetime.utcnow(),
            )
            session.add(log_entry)
            session.commit()
        except Exception as exc:
            session.rollback()
            logger.error("Failed to log notification: %s", exc)
        finally:
            session.close()


# Module-level singleton
_dispatcher: Optional[NotificationDispatcher] = None


def get_notification_dispatcher() -> NotificationDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher()
    return _dispatcher
