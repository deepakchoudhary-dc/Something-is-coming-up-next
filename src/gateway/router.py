"""
Gateway Router - Core API endpoints for AI Security Gateway
"""

import time
import logging
import re
import json
import uuid
import ipaddress
import socket
import secrets
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Depends, Header, status, Response
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import text

from ..filters.input_filter import InputFilter
from ..classifiers.ai_classifier import AIClassifier
from ..classifiers.semantic_detector import SemanticDetector
from ..monitoring.logger import log_transaction, detect_anomaly, set_request_id, get_request_id
from ..monitoring.database import SessionLocal, SecurityLog, HITLRequest, PolicyConfig, GatewayConfig
from ..monitoring.metrics import get_metrics
from ..monitoring.incident_export import export_incident
from ..policy.policy_manager import PolicyManager
from ..hitl.hitl_manager import HITLManager
from ..sandbox.sandbox_manager import SandboxManager
from ..config.settings import settings
from ..auth.tenant import CurrentUser, get_current_user
from ..auth.rbac import require_role, require_admin, require_reviewer, require_auditor
from ..auth.jwt_auth import create_access_token, TokenError
from ..providers.base import LLMMessage, ProviderError
from ..providers.router_provider import ProviderRouter
from ..secrets.secrets_manager import get_secrets_manager

router = APIRouter()
logger = logging.getLogger(__name__)
_classifier_instance: Optional[AIClassifier] = None
_provider_router: Optional[ProviderRouter] = None


def get_classifier() -> AIClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = AIClassifier()
    return _classifier_instance


def get_provider_router() -> ProviderRouter:
    global _provider_router
    if _provider_router is None:
        _provider_router = ProviderRouter()
    return _provider_router


# Request and Response schemas
class AIRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=settings.MAX_PROMPT_LENGTH)
    system_prompt: Optional[str] = Field(None, max_length=4000)
    retrieved_context: Optional[str] = Field(None, max_length=20000)
    user_id: str = Field(..., min_length=1, max_length=100)
    context: Optional[str] = Field(None, max_length=10000)
    model: Optional[str] = Field("gpt-3.5-turbo", min_length=1, max_length=100)
    execute_code: Optional[bool] = False

    @validator("user_id")
    def validate_user_id(cls, value):
        if not re.match(r"^[A-Za-z0-9_.:@-]+$", value):
            raise ValueError("user_id contains invalid characters")
        return value

    @validator("system_prompt", always=True)
    def enforce_server_system_prompt(cls, value):
        if settings.ALLOW_CLIENT_SYSTEM_PROMPT:
            return value or settings.DEFAULT_SYSTEM_PROMPT
        return settings.DEFAULT_SYSTEM_PROMPT

class AIResponse(BaseModel):
    response: str
    security_score: float
    flagged: bool
    processing_time: float
    action_taken: str
    request_id: Optional[str] = None
    sandbox_result: Optional[Dict[str, Any]] = None
    anomalies: List[Dict[str, Any]] = []
    trace: List[Dict[str, Any]] = []

class HITLDecision(BaseModel):
    approved: bool
    admin_name: Optional[str] = "Admin"

class HITLAssignment(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=200)

class PolicyUpdate(BaseModel):
    policies: Dict[str, Any]

class GatewayConfigUpdate(BaseModel):
    primary_provider: str = Field(...)
    primary_url: str = Field("", max_length=255)
    primary_key: str = Field("", max_length=512)
    primary_model: str = Field(..., min_length=1, max_length=100)
    fallback_enabled: bool
    fallback_provider: str = Field(...)
    fallback_url: str = Field("", max_length=255)
    fallback_key: str = Field("", max_length=512)
    fallback_model: str = Field(..., min_length=1, max_length=100)
    allowed_topics: str = Field("", max_length=500)

    @validator("primary_provider", "fallback_provider")
    def validate_provider(cls, value):
        if value not in {"mock", "openai", "anthropic", "custom"}:
            raise ValueError("provider must be one of: mock, openai, anthropic, custom")
        return value

    @validator("primary_url")
    def validate_primary_url(cls, value, values):
        if values.get("primary_provider") == "mock":
            return value
        _validate_outbound_url(value)
        return value

    @validator("fallback_url")
    def validate_fallback_url(cls, value, values):
        if values.get("fallback_provider") == "mock":
            return value
        _validate_outbound_url(value)
        return value


class IncidentExportRequest(BaseModel):
    start_time: str = Field(..., description="ISO-8601 UTC start time")
    end_time: str = Field(..., description="ISO-8601 UTC end time")
    include_prompts: bool = False
    include_responses: bool = False
    tenant_id: Optional[str] = None


class TokenRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    tenant_id: str = Field("default", min_length=1, max_length=100)
    roles: List[str] = Field(default_factory=lambda: ["user"])


# ── Legacy auth compat (kept for API-key mode) ────────────────────────
def require_user_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not settings.REQUIRE_AUTH:
        return
    if not settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_admin_api_key(
    x_admin_token: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None)
):
    if not (settings.REQUIRE_ADMIN_AUTH or settings.ADMIN_API_KEY):
        return
    if not settings.ADMIN_API_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Admin authentication is not configured")
    token = x_admin_token
    if token is None and settings.ALLOW_ADMIN_AUTH_VIA_USER_KEY:
        token = x_api_key
    if not token or not secrets.compare_digest(token, settings.ADMIN_API_KEY):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin authentication required")


def _get_auth_dependency():
    """Return the appropriate auth dependency based on AUTH_MODE."""
    if getattr(settings, "AUTH_MODE", "api_key") == "jwt":
        return Depends(get_current_user)
    return Depends(require_user_api_key)


def _get_admin_dependency():
    """Return the appropriate admin auth dependency based on AUTH_MODE."""
    if getattr(settings, "AUTH_MODE", "api_key") == "jwt":
        return Depends(require_role("admin"))
    return Depends(require_admin_api_key)


def _validate_outbound_url(url: str):
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Outbound model URL must be HTTPS with a hostname")

    if settings.ALLOW_PRIVATE_MODEL_URLS:
        return

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as ex:
        raise ValueError(f"Cannot resolve outbound model hostname: {parsed.hostname}") from ex

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise ValueError("Outbound model URL resolves to a non-public network address")

# Helper function to extract python code block from a prompt
def extract_python_code(text: str) -> Optional[str]:
    pattern = r"```python\s*(.*?)\s*```"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1)
    return None

@router.post("/process", response_model=AIResponse, dependencies=[Depends(require_user_api_key)])
async def process_ai_request(request: AIRequest):
    """
    Process an AI request through the security gateway
    """
    start_time = time.time()
    request_id = get_request_id() or set_request_id()
    metrics = get_metrics()
    metrics.inc("requests_total")
    action_taken = "allowed"
    sandbox_result = None
    flagged = False
    security_score = 0.0
    sanitized_prompt = request.prompt
    response_text = ""
    anomalies_list = []
    trace_events: List[Dict[str, Any]] = []

    def add_trace(stage: str, status: str, details: Dict[str, Any]):
        trace_events.append({
            "stage": stage,
            "status": status,
            "request_id": request_id,
            "details": details
        })

    def finalize_response() -> AIResponse:
        duration = time.time() - start_time
        metrics.observe("request_duration_seconds", duration)

        # Update action-specific counters
        if "blocked" in action_taken:
            metrics.inc("requests_blocked")
        elif action_taken == "redacted_output":
            metrics.inc("requests_redacted")
        elif "hitl" in action_taken:
            metrics.inc("requests_hitl")
        elif "failover" in action_taken:
            metrics.inc("requests_failover")
        else:
            metrics.inc("requests_allowed")

        log_transaction(
            user_id=request.user_id,
            prompt=request.prompt,
            response=response_text,
            risk_score=security_score,
            flagged=flagged,
            duration=duration,
            anomalies=anomalies_list,
            action_taken=action_taken,
            system_prompt=request.system_prompt,
            retrieved_context=request.retrieved_context,
            trace=trace_events
        )
        return AIResponse(
            response=response_text,
            security_score=security_score,
            flagged=flagged,
            processing_time=duration,
            action_taken=action_taken,
            request_id=request_id,
            sandbox_result=sandbox_result,
            anomalies=anomalies_list,
            trace=trace_events
        )

    # Fetch gateway configuration
    session = SessionLocal()
    gw_config = None
    try:
        gw_config = session.query(GatewayConfig).first()
    except Exception as db_err:
        logger.error(f"Failed to fetch config from database: {db_err}")
    finally:
        session.close()

    allowed_topics_str = gw_config.allowed_topics if gw_config else ""

    try:
        policy_manager = PolicyManager()

        # Step 0A: Rate Limiting Check
        rate_limit_result = policy_manager.check_rate_limit(request.user_id)
        if not rate_limit_result.get("allowed", True):
            action_taken = "blocked_rate_limit"
            flagged = True
            security_score = 0.5
            response_text = rate_limit_result.get("reason", "Blocked: Rate limit exceeded.")
            add_trace("rate_limiting", "blocked", {
                "user_id": request.user_id,
                "reason": response_text
            })
            anomalies_list.append({
                "type": "rate_limiting_violation",
                "description": response_text
            })
            return finalize_response()

        add_trace("rate_limiting", "passed", {
            "user_id": request.user_id
        })

        # Step 0B: User Access & Model Restriction Check
        access_result = policy_manager.check_user_access(request.user_id, request.model)
        if not access_result.get("allowed", True):
            action_taken = "blocked_access_violation"
            flagged = True
            security_score = 0.6
            response_text = access_result.get("reason", "Blocked: Access policy violation.")
            add_trace("user_access", "blocked", {
                "user_id": request.user_id,
                "reason": response_text
            })
            anomalies_list.append({
                "type": "user_access_violation",
                "description": response_text
            })
            return finalize_response()

        add_trace("user_access", "passed", {
            "user_id": request.user_id
        })

        input_filter = InputFilter()

        # Step 1A: Direct Input Sanitization & Validation
        sanitized_prompt = input_filter.sanitize(request.prompt)
        add_trace("input_sanitization", "passed", {
            "input_length": len(request.prompt),
            "sanitized_length": len(sanitized_prompt)
        })

        # Step 1B: Conversational Topic-Lock Rail Check
        if allowed_topics_str:
            if input_filter.is_out_of_topic(sanitized_prompt, allowed_topics_str):
                action_taken = "blocked_topic_violation"
                flagged = True
                security_score = 0.8
                response_text = f"Blocked: Request topic is out-of-scope. Allowed categories: {allowed_topics_str}."
                add_trace("topic_lock", "blocked", {
                    "allowed_topics": allowed_topics_str,
                    "reason": "request is out of scope"
                })
                
                return finalize_response()

            add_trace("topic_lock", "passed", {
                "allowed_topics": allowed_topics_str
            })

        # Check anomalous behaviors in user prompt
        anomaly_check = detect_anomaly({"prompt": sanitized_prompt})
        if anomaly_check["detected"]:
            anomalies_list.extend(anomaly_check["anomalies"])
            add_trace("anomaly_scan", "flagged", {
                "anomalies_found": len(anomaly_check["anomalies"])
            })
        else:
            add_trace("anomaly_scan", "clear", {
                "anomalies_found": 0
            })

        if input_filter.is_malicious(request.prompt) or input_filter.is_malicious(sanitized_prompt):
            action_taken = "blocked_input"
            flagged = True
            security_score = 1.0
            response_text = "Blocked: Request violates input security policy."
            add_trace("input_filter", "blocked", {
                "reason": "malicious prompt pattern matched"
            })
            
            return finalize_response()

        add_trace("input_filter", "passed", {
            "reason": "no malicious patterns detected"
        })

        # Step 1B.5: Semantic Vector Similarity Jailbreak Check
        input_policies = policy_manager.policies.get("input_validation")
        if input_policies and input_policies.enabled:
            rules = input_policies.rules
            templates = rules.get("jailbreak_templates", [])
            threshold = rules.get("semantic_threshold", 0.65)
            
            if templates:
                detector = SemanticDetector()
                detector.fit_templates(templates)
                sem_result = detector.check_similarity(sanitized_prompt, threshold)
                
                if sem_result["flagged"]:
                    action_taken = "blocked_semantic_jailbreak"
                    flagged = True
                    security_score = sem_result["score"]
                    response_text = f"Blocked: Request matches a known semantic jailbreak pattern (similarity: {sem_result['score']:.2f})."
                    add_trace("semantic_jailbreak_check", "blocked", {
                        "similarity_score": sem_result["score"],
                        "threshold": threshold,
                        "matched_pattern": sem_result["matched_pattern"]
                    })
                    anomalies_list.append({
                        "type": "semantic_jailbreak_violation",
                        "description": response_text
                    })
                    return finalize_response()

        add_trace("semantic_jailbreak_check", "passed", {
            "reason": "no semantic jailbreak patterns matched"
        })

        # Step 1C: Indirect Prompt Injection Check (RAG)
        if request.retrieved_context:
            sanitized_context = input_filter.sanitize(request.retrieved_context)
            if input_filter.is_indirect_injection(sanitized_context):
                action_taken = "blocked_indirect_injection"
                flagged = True
                security_score = 1.0
                response_text = "Blocked: Malicious instructions detected in retrieved RAG context."
                add_trace("rag_injection_scan", "blocked", {
                    "reason": "malicious instructions detected in retrieved context"
                })
                
                return finalize_response()

            add_trace("rag_injection_scan", "passed", {
                "reason": "no indirect injection detected"
            })
        else:
            add_trace("rag_injection_scan", "skipped", {
                "reason": "no retrieved context provided"
            })

        # Step 2: AI-powered Classification
        classifier = get_classifier()
        classification = classifier.classify(sanitized_prompt)
        security_score = classification.get("score", 0.0)
        flagged = classification.get("flagged", False)
        add_trace("classification", "complete", {
            "score": security_score,
            "flagged": flagged,
            "categories": classification.get("categories", [])
        })

        # Step 3: Policy Check & HITL Routing
        policy_manager = PolicyManager()
        if not policy_manager.check_policy(request.user_id, classification):
            action_taken = "hitl_pending"
            add_trace("policy_check", "escalated", {
                "reason": "policy rules required human review"
            })
            # Route to Human-in-the-Loop review
            hitl_manager = HITLManager()

            if not settings.HITL_BLOCKING_WAIT:
                hitl_state = await hitl_manager.create_request(request)
                if not hitl_state.get("created") and not hitl_state.get("approved"):
                    action_taken = "hitl_queue_error"
                    flagged = True
                    response_text = "Blocked: Request requires human review, but the review queue is unavailable."
                    add_trace("hitl_review", "queue_error", {
                        "reason": "failed to create human review request"
                    })
                    return finalize_response()
                if hitl_state.get("approved"):
                    action_taken = "hitl_disabled"
                    add_trace("hitl_review", "skipped", {
                        "reason": "HITL is disabled"
                    })
                else:
                    response_text = f"Pending human security review. Review ID: {hitl_state['request_id']}."
                    add_trace("hitl_review", "pending", {
                        "request_id": hitl_state["request_id"]
                    })
                    return finalize_response()
            else:
                approved = await hitl_manager.request_approval(request)
                if not approved:
                    action_taken = "hitl_denied"
                    response_text = "Blocked: Request denied by human security reviewer."
                    add_trace("hitl_review", "denied", {
                        "reason": "human reviewer denied execution"
                    })
                    return finalize_response()
                action_taken = "hitl_approved"
                add_trace("hitl_review", "approved", {
                    "reason": "human reviewer approved execution"
                })
        else:
            add_trace("policy_check", "passed", {
                "reason": "policy rules satisfied"
            })

        if action_taken == "hitl_disabled":
            add_trace("policy_check", "continued", {
                "reason": "HITL disabled, continuing after policy escalation"
            })
        elif action_taken == "hitl_pending":
            # Non-blocking HITL returns above. This guard keeps the later execution path explicit.
            response_text = "Pending human security review."
            return finalize_response()

        # Step 4: Sandbox Execution (if requested & code is found)
        code_snippet = extract_python_code(sanitized_prompt)
        if request.execute_code and not settings.SANDBOX_EXECUTION_ENABLED:
            action_taken = "blocked_sandbox_disabled"
            flagged = True
            security_score = max(security_score, 0.7)
            response_text = "Blocked: Code execution is disabled by gateway policy."
            add_trace("sandbox_execution", "blocked", {
                "reason": "sandbox execution disabled"
            })
            return finalize_response()

        if request.execute_code and code_snippet:
            sandbox = SandboxManager()
            sandbox_res = sandbox.execute_code(code_snippet, "python")
            sandbox_result = {
                "success": sandbox_res.get("success", False),
                "output": sandbox_res.get("output", ""),
                "error": sandbox_res.get("error", None)
            }
            add_trace("sandbox_execution", "complete", {
                "requested": True,
                "success": sandbox_result["success"]
            })
            if not sandbox_res.get("success", False):
                # Sandbox failed or blocked execution
                action_taken = "blocked_sandbox_violation"
                response_text = f"Blocked: Code execution failed safety check. Details: {sandbox_res.get('error')}"
                add_trace("sandbox_execution", "blocked", {
                    "reason": sandbox_res.get('error')
                })
                return finalize_response()

        # Step 5: Generate model response via ProviderRouter
        if sandbox_result:
            if sandbox_result["success"]:
                response_text = f"Code executed successfully.\n[OUTPUT]\n{sandbox_result['output']}"
            else:
                response_text = f"Code failed execution.\n[ERROR]\n{sandbox_result['error']}"
        else:
            provider_type = gw_config.primary_provider if gw_config else "mock"
            add_trace("model_routing", "selected", {
                "provider": provider_type,
                "primary_model": gw_config.primary_model if gw_config else "mock"
            })

            if provider_type == "mock" and (not gw_config or not gw_config.primary_key):
                response_text = "Processed successfully."
                add_trace("model_routing", "mock_response", {
                    "reason": "no external provider configured"
                })
            else:
                # Resolve secrets from references
                sm = get_secrets_manager()
                primary_key = sm.get_secret(gw_config.primary_key) if gw_config and gw_config.primary_key else ""
                fallback_key = sm.get_secret(gw_config.fallback_key) if gw_config and gw_config.fallback_key else ""

                try:
                    pr = get_provider_router()
                    messages = []
                    if request.system_prompt:
                        messages.append(LLMMessage(role="system", content=request.system_prompt))
                    if request.retrieved_context:
                        messages.append(LLMMessage(role="user", content=f"Context details:\n{request.retrieved_context}"))
                    messages.append(LLMMessage(role="user", content=sanitized_prompt))

                    llm_response = pr.complete(
                        messages=messages,
                        primary_provider_type=gw_config.primary_provider,
                        primary_url=gw_config.primary_url,
                        primary_key=primary_key,
                        primary_model=gw_config.primary_model,
                        fallback_enabled=gw_config.fallback_enabled if gw_config else False,
                        fallback_provider_type=gw_config.fallback_provider if gw_config else "mock",
                        fallback_url=gw_config.fallback_url if gw_config else "",
                        fallback_key=fallback_key,
                        fallback_model=gw_config.fallback_model if gw_config else "",
                    )
                    response_text = llm_response.content

                    if "fallback" in llm_response.provider:
                        action_taken = "failover_routing"
                        metrics.inc("requests_failover")
                        anomalies_list.append({
                            "type": "resilience_failover",
                            "description": "Primary model failed. Routed to fallback provider."
                        })
                        add_trace("model_routing", "failover", {
                            "provider": llm_response.provider,
                            "latency_ms": llm_response.latency_ms,
                        })
                    else:
                        add_trace("model_routing", "complete", {
                            "provider": llm_response.provider,
                            "latency_ms": llm_response.latency_ms,
                            "tokens": llm_response.usage.total_tokens,
                        })
                except ProviderError as exc:
                    logger.error("Provider routing failed: %s", exc)
                    response_text = "Gateway Connection Error: Outbound LLM requests failed."
                    action_taken = "blocked_network_error"
                    flagged = True
                    add_trace("model_routing", "failed", {
                        "error": str(exc)
                    })

        # Step 6: Output System Prompt Leakage & Verification
        if request.system_prompt and input_filter.detect_system_leak(response_text, request.system_prompt):
            action_taken = "blocked_system_leak"
            flagged = True
            security_score = 0.9
            response_text = "Blocked: Response contains sensitive system instructions."
            add_trace("output_leakage_guard", "blocked", {
                "reason": "system prompt overlap exceeded threshold"
            })
            anomalies_list.append({
                "type": "system_leakage_guard",
                "description": "Output blocked to prevent disclosure of system prompt instructions."
            })
        else:
            # Output Filtering (PII Redactions)
            filtered_response = input_filter.filter_output(response_text)
            if filtered_response != response_text:
                anomalies_list.append({
                    "type": "data_leak_redaction",
                    "description": "Sensitive patterns (PII/keys) were redacted from the AI response."
                })
                if action_taken == "allowed":
                    action_taken = "redacted_output"
                add_trace("output_redaction", "modified", {
                    "reason": "sensitive output patterns were redacted"
                })
            else:
                add_trace("output_redaction", "passed", {
                    "reason": "no sensitive output patterns detected"
                })
            response_text = filtered_response

        # Step 7: Final Transaction Log & Return
        add_trace("request_complete", "done", {
            "final_action": action_taken,
            "flagged": flagged,
            "security_score": security_score
        })

        return finalize_response()

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ── Auth Token Endpoint ───────────────────────────────────────────────
@router.post("/auth/token", dependencies=[Depends(require_admin_api_key)])
async def issue_token(req: TokenRequest):
    """Issue a JWT access token (admin-only in API-key mode)."""
    try:
        token = create_access_token(
            subject=req.subject,
            tenant_id=req.tenant_id,
            roles=req.roles,
        )
        return {"access_token": token, "token_type": "bearer"}
    except TokenError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Gateway Config Endpoints ──────────────────────────────────────────
@router.get("/config", dependencies=[Depends(require_admin_api_key)])
async def get_gateway_config():
    """Retrieve the current gateway configuration with masked keys"""
    session = SessionLocal()
    try:
        config = session.query(GatewayConfig).first()
        if not config:
            return {}
        
        def mask_key(k):
            if not k:
                return ""
            if len(k) <= 8:
                return "********"
            return k[:4] + "..." + k[-4:]

        return {
            "primary_provider": config.primary_provider,
            "primary_url": config.primary_url,
            "primary_key": mask_key(config.primary_key),
            "primary_model": config.primary_model,
            "fallback_enabled": config.fallback_enabled,
            "fallback_provider": config.fallback_provider,
            "fallback_url": config.fallback_url,
            "fallback_key": mask_key(config.fallback_key),
            "fallback_model": config.fallback_model,
            "allowed_topics": config.allowed_topics
        }
    finally:
        session.close()

@router.post("/config", dependencies=[Depends(require_admin_api_key)])
async def update_gateway_config(update: GatewayConfigUpdate):
    """Update gateway configuration, storing keys as secret references"""
    sm = get_secrets_manager()
    session = SessionLocal()
    try:
        config = session.query(GatewayConfig).first()
        if not config:
            config = GatewayConfig()
            session.add(config)
        
        config.primary_provider = update.primary_provider
        config.primary_url = update.primary_url
        # Only update keys if the value isn't a masked placeholder
        if not sm.is_masked(update.primary_key):
            if update.primary_key and not sm.is_reference(update.primary_key):
                config.primary_key = sm.store_secret(update.primary_key, path=f"GATEWAY_PRIMARY_KEY")
            else:
                config.primary_key = update.primary_key
            
        config.primary_model = update.primary_model
        config.fallback_enabled = update.fallback_enabled
        config.fallback_provider = update.fallback_provider
        config.fallback_url = update.fallback_url
        if not sm.is_masked(update.fallback_key):
            if update.fallback_key and not sm.is_reference(update.fallback_key):
                config.fallback_key = sm.store_secret(update.fallback_key, path=f"GATEWAY_FALLBACK_KEY")
            else:
                config.fallback_key = update.fallback_key
            
        config.fallback_model = update.fallback_model
        config.allowed_topics = update.allowed_topics
        
        session.commit()
        return {"status": "success", "message": "Gateway integrations updated."}
    except Exception as e:
        session.rollback()
        logger.error("Gateway config update failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Gateway config update failed")
    finally:
        session.close()


# Policy Management Endpoints
@router.get("/policies", dependencies=[Depends(require_admin_api_key)])
async def get_policies():
    """Get current security policies from database"""
    policy_manager = PolicyManager()
    return policy_manager.get_policies()

@router.post("/policies", dependencies=[Depends(require_admin_api_key)])
async def update_policies(update: PolicyUpdate):
    """Update security policies in database"""
    policy_manager = PolicyManager()
    return policy_manager.update_policies(update.policies)


# Human-in-the-Loop endpoints
@router.get("/hitl/pending", dependencies=[Depends(require_admin_api_key)])
async def get_hitl_pending():
    """Fetch all pending manual approvals"""
    hitl_manager = HITLManager()
    return hitl_manager.get_pending_requests()

@router.post("/hitl/approve/{request_id}", dependencies=[Depends(require_admin_api_key)])
async def approve_hitl_request(request_id: str, decision: HITLDecision):
    """Approve or deny a pending request"""
    hitl_manager = HITLManager()
    success = await hitl_manager.approve_request(
        request_id=request_id,
        approved=decision.approved,
        admin_name=decision.admin_name
    )
    if not success:
        raise HTTPException(status_code=404, detail="Request not found or not in pending state")
    return {"status": "success", "message": f"Request {request_id} has been {'approved' if decision.approved else 'denied'}"}

@router.get("/hitl/status/{request_id}", dependencies=[Depends(require_admin_api_key)])
async def get_hitl_status(request_id: str):
    """Get the status of a specific HITL request"""
    hitl_manager = HITLManager()
    details = hitl_manager.get_request_details(request_id)
    if not details:
        raise HTTPException(status_code=404, detail="Request not found")
    return details

@router.post("/hitl/assign/{request_id}", dependencies=[Depends(require_admin_api_key)])
async def assign_hitl_request(request_id: str, assignment: HITLAssignment):
    """Assign a reviewer to a pending HITL request"""
    hitl_manager = HITLManager()
    success = hitl_manager.assign_reviewer(request_id, assignment.assigned_to)
    if not success:
        raise HTTPException(status_code=404, detail="Request not found or not in pending state")
    return {"status": "success", "message": f"Request {request_id} assigned to {assignment.assigned_to}"}

@router.get("/hitl/history", dependencies=[Depends(require_admin_api_key)])
async def get_hitl_history(limit: int = 50, offset: int = 0):
    """Get completed HITL review history"""
    hitl_manager = HITLManager()
    return hitl_manager.get_completed_history(limit=limit, offset=offset)


# Monitoring, Auditing & Logs Endpoints
@router.get("/monitoring/logs", dependencies=[Depends(require_admin_api_key)])
async def get_security_logs(limit: int = 50, offset: int = 0, action: Optional[str] = None):
    """Retrieve security transaction logs from SQLite"""
    session = SessionLocal()
    try:
        query = session.query(SecurityLog)
        if action:
            query = query.filter(SecurityLog.action_taken == action)
        
        logs = query.order_by(SecurityLog.timestamp.desc()).offset(offset).limit(limit).all()
        
        results = []
        for l in logs:
            try:
                anoms = json.loads(l.anomalies)
            except Exception:
                anoms = []
            try:
                trace = json.loads(l.trace_json) if getattr(l, "trace_json", None) else []
            except Exception:
                trace = []
            results.append({
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "client_ip": l.client_ip,
                "user_id": l.user_id,
                "prompt": l.prompt,
                "response": l.response,
                "risk_score": l.risk_score,
                "flagged": l.flagged,
                "duration": l.duration,
                "anomalies": anoms,
                "trace": trace,
                "action_taken": l.action_taken,
                "request_id": getattr(l, "request_id", None),
            })
        return results
    except Exception as e:
        logger.error(f"Error querying logs: {e}")
        raise HTTPException(status_code=500, detail="Database log query failed")
    finally:
        session.close()

@router.get("/monitoring/stats", dependencies=[Depends(require_admin_api_key)])
async def get_dashboard_stats():
    """Retrieve dashboard statistics & aggregates"""
    session = SessionLocal()
    try:
        # Aggregations
        total = session.query(SecurityLog).count()
        flagged = session.query(SecurityLog).filter(SecurityLog.flagged == True).count()
        blocked = session.query(SecurityLog).filter(SecurityLog.action_taken.like("blocked%")).count()
        hitl_pending = session.query(HITLRequest).filter(HITLRequest.status == "pending").count()
        
        # Update gauge
        get_metrics().set_gauge("active_hitl_pending", hitl_pending)

        # Calculate rates
        block_rate = (blocked / total * 100) if total > 0 else 0.0
        flag_rate = (flagged / total * 100) if total > 0 else 0.0

        # Calculate average duration
        avg_dur_res = session.execute(text("SELECT AVG(duration) FROM security_logs")).scalar()
        avg_dur = float(avg_dur_res) if avg_dur_res is not None else 0.0

        # Calculate average security risk score
        avg_score_res = session.execute(text("SELECT AVG(risk_score) FROM security_logs")).scalar()
        avg_score = float(avg_score_res) if avg_score_res is not None else 0.0

        # Recent transaction summary for charts
        # Group by action
        action_counts = {}
        for action in ["allowed", "blocked_input", "blocked_output", "hitl_approved", "hitl_denied", "blocked_sandbox_violation", "redacted_output"]:
            cnt = session.query(SecurityLog).filter(SecurityLog.action_taken == action).count()
            action_counts[action] = cnt

        # Get activity graph points (last 7 days)
        activity_points = []
        for i in range(6, -1, -1):
            day_date = datetime.utcnow().date() - timedelta(days=i)
            day_str = day_date.strftime("%Y-%m-%d")
            
            day_start = datetime.combine(day_date, datetime.min.time())
            day_end = datetime.combine(day_date, datetime.max.time())
            
            day_total = session.query(SecurityLog).filter(SecurityLog.timestamp >= day_start, SecurityLog.timestamp <= day_end).count()
            day_flagged = session.query(SecurityLog).filter(SecurityLog.timestamp >= day_start, SecurityLog.timestamp <= day_end, SecurityLog.flagged == True).count()
            
            activity_points.append({
                "date": day_str,
                "label": day_date.strftime("%a"),
                "total": day_total,
                "flagged": day_flagged
            })

        return {
            "total_requests": total,
            "flagged_requests": flagged,
            "blocked_requests": blocked,
            "pending_hitl": hitl_pending,
            "block_rate": round(block_rate, 2),
            "flag_rate": round(flag_rate, 2),
            "avg_duration": round(avg_dur, 4),
            "avg_risk_score": round(avg_score, 4),
            "action_distribution": action_counts,
            "activity_timeline": activity_points
        }
    except Exception as e:
        logger.error(f"Error compiling stats: {e}")
        raise HTTPException(status_code=500, detail="Database aggregation failed")
    finally:
        session.close()


# ── Metrics Endpoint ──────────────────────────────────────────────────
@router.get("/monitoring/metrics", dependencies=[Depends(require_admin_api_key)])
async def get_metrics_endpoint(format: str = "json"):
    """Return gateway metrics in JSON or Prometheus text format."""
    m = get_metrics()
    if format == "prometheus":
        return Response(content=m.to_prometheus(), media_type="text/plain; charset=utf-8")
    return m.to_dict()


@router.get("/monitoring/alerts", dependencies=[Depends(require_admin_api_key)])
async def get_alerts(limit: int = 50):
    """Return recent alerting events."""
    return get_metrics().get_alerts(limit)


# ── Incident Export ───────────────────────────────────────────────────
@router.post("/monitoring/incidents/export", dependencies=[Depends(require_admin_api_key)])
async def export_incident_endpoint(req: IncidentExportRequest):
    """Export security logs for incident investigation with optional field redaction."""
    try:
        start = datetime.fromisoformat(req.start_time)
        end = datetime.fromisoformat(req.end_time)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid datetime format: {exc}")

    return export_incident(
        start_time=start,
        end_time=end,
        include_prompts=req.include_prompts,
        include_responses=req.include_responses,
        tenant_id=req.tenant_id,
    )


# ── Circuit Breaker Status ───────────────────────────────────────────
@router.get("/monitoring/circuit-breakers", dependencies=[Depends(require_admin_api_key)])
async def get_circuit_breaker_states():
    """Return current circuit breaker states for all providers."""
    return get_provider_router().get_circuit_states()


# Red Teaming endpoints
@router.get("/redteaming/payloads", dependencies=[Depends(require_admin_api_key)])
async def get_red_teaming_payloads():
    """Fetch versioned red-teaming payloads for testing"""
    if not settings.REDTEAM_ENDPOINTS_ENABLED:
        raise HTTPException(status_code=404, detail="Red-team endpoints are disabled")
    from ..redteaming.simulation import load_versioned_payloads
    return load_versioned_payloads()

@router.post("/redteaming/scan", dependencies=[Depends(require_admin_api_key)])
async def run_red_teaming_scan():
    """Initiate an automated red-teaming attack simulation against the gateway"""
    if not settings.REDTEAM_ENDPOINTS_ENABLED:
        raise HTTPException(status_code=404, detail="Red-team endpoints are disabled")
    from ..redteaming.simulation import RedTeamingSuite
    suite = RedTeamingSuite()
    report = await suite.run_automated_scan()
    return report

@router.get("/redteaming/reports", dependencies=[Depends(require_admin_api_key)])
async def get_redteam_reports(limit: int = 20):
    """Retrieve stored red-team scan reports"""
    if not settings.REDTEAM_ENDPOINTS_ENABLED:
        raise HTTPException(status_code=404, detail="Red-team endpoints are disabled")
    from ..redteaming.report_model import RedTeamReport
    session = SessionLocal()
    try:
        reports = session.query(RedTeamReport).order_by(RedTeamReport.timestamp.desc()).limit(limit).all()
        return [{
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "payload_version": r.payload_version,
            "scan_duration_seconds": r.scan_duration_seconds,
            "total_payloads": r.total_payloads,
            "blocked_count": r.blocked_count,
            "bypassed_count": r.bypassed_count,
            "bypass_rate": r.bypass_rate,
            "security_posture": r.security_posture,
        } for r in reports]
    finally:
        session.close()
