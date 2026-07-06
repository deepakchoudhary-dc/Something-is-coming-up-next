"""
Database module for AI Security Gateway -- Handles persistence of logs, policies, configs, and HITL requests
"""

import os
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from ..config.settings import settings

logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
Base = declarative_base()

# Resolve database URL
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite:///"):
    # Ensure directory exists for sqlite files
    db_path = db_url.replace("sqlite:///", "")
    if db_path and not db_path.startswith("./") and not db_path.startswith("/"):
        dir_name = os.path.dirname(db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

engine = create_engine(db_url, connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {})
db_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SessionLocal = scoped_session(db_session)

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String(50), nullable=True)
    user_id = Column(String(100), index=True)
    
    # User Inputs & Dynamic Contexts
    prompt = Column(Text, nullable=False)
    system_prompt = Column(Text, nullable=True)
    retrieved_context = Column(Text, nullable=True)
    
    response = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
    flagged = Column(Boolean, default=False)
    duration = Column(Float, default=0.0)
    anomalies = Column(Text, default="[]")  # JSON string listing anomalies
    trace_json = Column(Text, default="[]")  # JSON string listing gateway trace events
    action_taken = Column(String(50), default="allowed")  # allowed, blocked_input, blocked_output, etc.

class HITLRequest(Base):
    __tablename__ = "hitl_requests"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # Request data stored separately for auditing/review
    prompt = Column(Text, nullable=False)
    system_prompt = Column(Text, nullable=True)
    retrieved_context = Column(Text, nullable=True)
    context = Column(Text, nullable=True)
    
    model = Column(String(100), default="unknown")
    user_id = Column(String(100), index=True)
    status = Column(String(50), default="pending", index=True)  # pending, approved, denied
    decision_by = Column(String(100), nullable=True)
    decision_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class PolicyConfig(Base):
    __tablename__ = "policy_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    rules_json = Column(Text, nullable=False)  # JSON representation of security rules
    enabled = Column(Boolean, default=True)

class GatewayConfig(Base):
    __tablename__ = "gateway_configs"

    id = Column(Integer, primary_key=True, index=True)
    
    # Primary configuration
    primary_provider = Column(String(50), default="mock")  # mock, openai, custom
    primary_url = Column(String(255), default="https://api.openai.com/v1/chat/completions")
    primary_key = Column(String(255), default="")
    primary_model = Column(String(100), default="gpt-3.5-turbo")
    
    # Fallback configuration
    fallback_enabled = Column(Boolean, default=False)
    fallback_provider = Column(String(50), default="mock")
    fallback_url = Column(String(255), default="")
    fallback_key = Column(String(255), default="")
    fallback_model = Column(String(100), default="gpt-3.5-turbo")
    
    # Topic limits rail config
    allowed_topics = Column(Text, default="")  # Comma-separated list of allowed topics (e.g., support, account)

def init_db():
    """Initialize database tables, dropping them first if we need to align the schemas"""
    session = SessionLocal()
    schema_outdated = False
    try:
        # Check if GatewayConfig exists and has the primary_provider column
        session.execute("SELECT primary_provider FROM gateway_configs LIMIT 1")
        session.execute("SELECT trace_json FROM security_logs LIMIT 1")
        session.execute("SELECT system_prompt FROM security_logs LIMIT 1")
    except Exception:
        schema_outdated = True
    finally:
        session.close()

    if schema_outdated:
        logger.warning("Outdated database schema detected. Dropping old tables to sync configs schema...")
        try:
            Base.metadata.drop_all(bind=engine)
        except Exception as ex:
            logger.error(f"Error dropping outdated tables: {ex}")

    Base.metadata.create_all(bind=engine)
    
    session = SessionLocal()
    try:
        # Seed configs table if empty
        if session.query(GatewayConfig).count() == 0:
            default_config = GatewayConfig(
                primary_provider="mock",
                primary_url="https://api.openai.com/v1/chat/completions",
                primary_key="",
                primary_model="gpt-3.5-turbo",
                fallback_enabled=False,
                fallback_provider="mock",
                fallback_url="",
                fallback_key="",
                fallback_model="gpt-3.5-turbo",
                allowed_topics=""
            )
            session.add(default_config)
            session.commit()

        # Seed policy table if empty
        if session.query(PolicyConfig).count() == 0:
            import json
            default_policies = [
                PolicyConfig(
                    name="input_validation",
                    description="Basic input validation and patterns",
                    rules_json=json.dumps({
                        "max_length": 10000,
                        "min_length": 1,
                        "block_patterns": [
                            "ignore previous instructions",
                            "ignore all previous",
                            "system prompt",
                            "override instructions",
                            "jailbreak",
                            "dan mode",
                            "developer mode"
                        ]
                    }),
                    enabled=True
                ),
                PolicyConfig(
                    name="content_filtering",
                    description="Content and toxicity filtering thresholds",
                    rules_json=json.dumps({
                        "toxicity_threshold": 0.7,
                        "block_categories": ["toxic", "threat", "insult"],
                        "allow_domains": ["business", "education", "general"]
                    }),
                    enabled=True
                ),
                PolicyConfig(
                    name="rate_limiting",
                    description="Access limits per time interval",
                    rules_json=json.dumps({
                        "requests_per_minute": 60,
                        "requests_per_hour": 1000,
                        "burst_limit": 10
                    }),
                    enabled=True
                ),
                PolicyConfig(
                    name="user_access",
                    description="Role-based permissions and caps",
                    rules_json=json.dumps({
                        "roles": {
                            "admin": {"all_access": True},
                            "user": {"max_requests": 100},
                            "guest": {"max_requests": 10, "restricted_models": True}
                        }
                    }),
                    enabled=True
                )
            ]
            session.add_all(default_policies)
            session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to load default database seed: {e}")
    finally:
        session.close()

def get_db():
    """Get DB session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
