"""Initial schema baseline

Revision ID: 001_initial
Revises: None
Create Date: 2026-07-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── security_logs ─────────────────────────────────────────────
    op.create_table(
        "security_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True, index=True),
        sa.Column("client_ip", sa.String(50), nullable=True),
        sa.Column("user_id", sa.String(100), nullable=True, index=True),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("retrieved_context", sa.Text(), nullable=True),
        sa.Column("response", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), default=0.0),
        sa.Column("flagged", sa.Boolean(), default=False),
        sa.Column("duration", sa.Float(), default=0.0),
        sa.Column("anomalies", sa.Text(), default="[]"),
        sa.Column("trace_json", sa.Text(), default="[]"),
        sa.Column("action_taken", sa.String(50), default="allowed"),
        sa.Column("request_id", sa.String(100), nullable=True, index=True),
        sa.Column("tenant_id", sa.String(100), nullable=True, index=True),
    )

    # ── hitl_requests ─────────────────────────────────────────────
    op.create_table(
        "hitl_requests",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("request_id", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("retrieved_context", sa.Text(), nullable=True),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("model", sa.String(100), default="unknown"),
        sa.Column("user_id", sa.String(100), nullable=True, index=True),
        sa.Column("status", sa.String(50), default="pending", index=True),
        sa.Column("decision_by", sa.String(100), nullable=True),
        sa.Column("decision_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True, index=True),
        sa.Column("assigned_to", sa.String(200), nullable=True),
        sa.Column("escalated_at", sa.DateTime(), nullable=True),
        sa.Column("notification_sent", sa.Boolean(), default=False),
        sa.Column("tenant_id", sa.String(100), nullable=True, index=True),
    )

    # ── policy_configs ────────────────────────────────────────────
    op.create_table(
        "policy_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("rules_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), default=True),
    )

    # ── gateway_configs ───────────────────────────────────────────
    op.create_table(
        "gateway_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("primary_provider", sa.String(50), default="mock"),
        sa.Column("primary_url", sa.String(255), default="https://api.openai.com/v1/chat/completions"),
        sa.Column("primary_key", sa.String(255), default=""),
        sa.Column("primary_model", sa.String(100), default="gpt-3.5-turbo"),
        sa.Column("fallback_enabled", sa.Boolean(), default=False),
        sa.Column("fallback_provider", sa.String(50), default="mock"),
        sa.Column("fallback_url", sa.String(255), default=""),
        sa.Column("fallback_key", sa.String(255), default=""),
        sa.Column("fallback_model", sa.String(100), default="gpt-3.5-turbo"),
        sa.Column("allowed_topics", sa.Text(), default=""),
    )

    # ── tenants ───────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(200), unique=True, nullable=False, index=True),
        sa.Column("api_key_hash", sa.String(255), nullable=True),
        sa.Column("settings_json", sa.Text(), default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # ── tenant_users ──────────────────────────────────────────────
    op.create_table(
        "tenant_users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.String(200), nullable=False, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("role", sa.String(50), default="user", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # ── secret_access_logs ────────────────────────────────────────
    op.create_table(
        "secret_access_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True, index=True),
        sa.Column("action", sa.String(50), nullable=False, index=True),
        sa.Column("reference", sa.String(500), nullable=False),
        sa.Column("actor", sa.String(200), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
    )

    # ── notification_logs ─────────────────────────────────────────
    op.create_table(
        "notification_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True, index=True),
        sa.Column("channel", sa.String(50), nullable=False),
        sa.Column("recipient", sa.String(500), nullable=True),
        sa.Column("subject", sa.String(500), nullable=True),
        sa.Column("status", sa.String(50), default="sent"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("payload_summary", sa.Text(), nullable=True),
    )

    # ── redteam_reports ───────────────────────────────────────────
    op.create_table(
        "redteam_reports",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True, index=True),
        sa.Column("payload_version", sa.String(50), default="1.0"),
        sa.Column("scan_duration_seconds", sa.Float(), default=0.0),
        sa.Column("total_payloads", sa.Integer(), default=0),
        sa.Column("malicious_tested", sa.Integer(), default=0),
        sa.Column("benign_tested", sa.Integer(), default=0),
        sa.Column("blocked_count", sa.Integer(), default=0),
        sa.Column("bypassed_count", sa.Integer(), default=0),
        sa.Column("bypass_rate", sa.Float(), default=0.0),
        sa.Column("security_posture", sa.String(50), default="unknown"),
        sa.Column("results_json", sa.Text(), default="[]"),
        sa.Column("metrics_json", sa.Text(), default="{}"),
    )


def downgrade() -> None:
    op.drop_table("redteam_reports")
    op.drop_table("notification_logs")
    op.drop_table("secret_access_logs")
    op.drop_table("tenant_users")
    op.drop_table("tenants")
    op.drop_table("gateway_configs")
    op.drop_table("policy_configs")
    op.drop_table("hitl_requests")
    op.drop_table("security_logs")
