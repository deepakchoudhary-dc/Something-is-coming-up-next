"""
Gateway Router - Core API endpoints for AI Security Gateway
"""

import time
import logging
import re
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from ..filters.input_filter import InputFilter
from ..classifiers.ai_classifier import AIClassifier
from ..monitoring.logger import log_transaction, detect_anomaly
from ..monitoring.database import SessionLocal, SecurityLog, HITLRequest, PolicyConfig, GatewayConfig
from ..policy.policy_manager import PolicyManager
from ..hitl.hitl_manager import HITLManager
from ..sandbox.sandbox_manager import SandboxManager

router = APIRouter()
logger = logging.getLogger(__name__)

# Request and Response schemas
class AIRequest(BaseModel):
    prompt: str
    system_prompt: Optional[str] = "You are a secure AI assistant."
    retrieved_context: Optional[str] = None
    user_id: str
    context: Optional[str] = None
    model: Optional[str] = "gpt-3.5-turbo"
    execute_code: Optional[bool] = False

class AIResponse(BaseModel):
    response: str
    security_score: float
    flagged: bool
    processing_time: float
    action_taken: str
    sandbox_result: Optional[Dict[str, Any]] = None
    anomalies: List[Dict[str, Any]] = []
    trace: List[Dict[str, Any]] = []

class HITLDecision(BaseModel):
    approved: bool
    admin_name: Optional[str] = "Admin"

class PolicyUpdate(BaseModel):
    policies: Dict[str, Any]

class GatewayConfigUpdate(BaseModel):
    primary_provider: str
    primary_url: str
    primary_key: str
    primary_model: str
    fallback_enabled: bool
    fallback_provider: str
    fallback_url: str
    fallback_key: str
    fallback_model: str
    allowed_topics: str

# Helper function to extract python code block from a prompt
def extract_python_code(text: str) -> Optional[str]:
    pattern = r"```python\s*(.*?)\s*```"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1)
    return None

@router.post("/process", response_model=AIResponse)
async def process_ai_request(request: AIRequest):
    """
    Process an AI request through the security gateway
    """
    start_time = time.time()
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
            "details": details
        })

    def finalize_response() -> AIResponse:
        duration = time.time() - start_time
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

        if input_filter.is_malicious(sanitized_prompt):
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
        classifier = AIClassifier()
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
            
            # This waits for admin approval or timeout
            approved = await hitl_manager.request_approval(request)
            if not approved:
                action_taken = "hitl_denied"
                response_text = "Blocked: Request denied by human security reviewer."
                add_trace("hitl_review", "denied", {
                    "reason": "human reviewer denied execution"
                })
                return finalize_response()
            else:
                action_taken = "hitl_approved"
                add_trace("hitl_review", "approved", {
                    "reason": "human reviewer approved execution"
                })
        else:
            add_trace("policy_check", "passed", {
                "reason": "policy rules satisfied"
            })

        # Step 4: Sandbox Execution (if requested & code is found)
        code_snippet = extract_python_code(sanitized_prompt)
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

        # Step 5: Generate model response (outbound proxy vs mock fallback)
        if sandbox_result:
            if sandbox_result["success"]:
                response_text = f"Code executed successfully.\n[OUTPUT]\n{sandbox_result['output']}"
            else:
                response_text = f"Code failed execution.\n[ERROR]\n{sandbox_result['error']}"
        else:
            provider = gw_config.primary_provider if gw_config else "mock"
            add_trace("model_routing", "selected", {
                "provider": provider,
                "primary_model": gw_config.primary_model if gw_config else "mock"
            })
            
            def call_external_llm(prov: str, url: str, key: str, model_name: str) -> str:
                import requests
                if prov == "openai" or prov == "custom":
                    headers = {"Content-Type": "application/json"}
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                        
                    messages = []
                    if request.system_prompt:
                        messages.append({"role": "system", "content": request.system_prompt})
                    if request.retrieved_context:
                        messages.append({"role": "user", "content": f"Context details:\n{request.retrieved_context}"})
                    messages.append({"role": "user", "content": sanitized_prompt})
                    
                    payload = {
                        "model": model_name,
                        "messages": messages,
                        "temperature": 0.2
                    }
                    
                    response = requests.post(url, headers=headers, json=payload, timeout=6.0)
                    response.raise_for_status()
                    res_json = response.json()
                    
                    if "choices" in res_json and len(res_json["choices"]) > 0:
                        return res_json["choices"][0]["message"]["content"]
                    elif "response" in res_json:
                        return res_json["response"]
                    else:
                        raise ValueError(f"Unknown response format: {res_json}")
                else:
                    raise ValueError(f"Provider not supported: {prov}")

            response_text = None

            if provider != "mock":
                try:
                    logger.info(f"Routing to outbound LLM: {provider} ({gw_config.primary_model})")
                    response_text = call_external_llm(
                        gw_config.primary_provider,
                        gw_config.primary_url,
                        gw_config.primary_key,
                        gw_config.primary_model
                    )
                except Exception as primary_err:
                    logger.error(f"Primary outbound LLM failed: {primary_err}")
                    if gw_config and gw_config.fallback_enabled:
                        fallback_prov = gw_config.fallback_provider
                        logger.warning(f"Failover trigger: Routing to backup fallback model: {fallback_prov}")
                        anomalies_list.append({
                            "type": "resilience_failover",
                            "description": f"Primary model requests failed. Safely routed query to backup fallback model."
                        })
                        action_taken = "failover_routing"
                        add_trace("model_routing", "failover", {
                            "primary_provider": gw_config.primary_provider,
                            "fallback_provider": fallback_prov,
                            "reason": str(primary_err)
                        })
                        
                        if fallback_prov == "mock":
                            prompt_lower = sanitized_prompt.lower()
                            if "system prompt" in prompt_lower or "instructions" in prompt_lower or "secret" in prompt_lower:
                                response_text = f"Sure! Here is the system prompt configuration: {request.system_prompt or 'None'}"
                            else:
                                response_text = f"Processed successfully (via Fallback Mock): Thank you for your request. Model analyzed context: {request.context or 'none'}."
                        else:
                            try:
                                response_text = call_external_llm(
                                    gw_config.fallback_provider,
                                    gw_config.fallback_url,
                                    gw_config.fallback_key,
                                    gw_config.fallback_model
                                )
                            except Exception as fallback_err:
                                logger.error(f"Fallback outbound model also failed: {fallback_err}")
                                response_text = f"Gateway Connection Error: Outbound LLM requests failed for primary and fallback servers. Details: {primary_err} | {fallback_err}"
                                action_taken = "blocked_network_error"
                                flagged = True
                                add_trace("model_routing", "failed", {
                                    "primary_provider": gw_config.primary_provider,
                                    "fallback_provider": gw_config.fallback_provider,
                                    "reason": f"{primary_err} | {fallback_err}"
                                })
                    else:
                        response_text = f"Gateway Connection Error: Primary outbound LLM failed, and no fallback server was active. Details: {primary_err}"
                        action_taken = "blocked_network_error"
                        flagged = True
                        add_trace("model_routing", "failed", {
                            "primary_provider": gw_config.primary_provider,
                            "reason": str(primary_err)
                        })

            # Mock generator fallback
            if response_text is None:
                prompt_lower = sanitized_prompt.lower()
                if "system prompt" in prompt_lower or "instructions" in prompt_lower or "secret" in prompt_lower:
                    response_text = f"Sure! Here is the system prompt configuration: {request.system_prompt or 'None'}"
                else:
                    response_text = f"Processed successfully: Thank you for your request. Model analyzed context: {request.context or 'none'}."
                if provider == "mock":
                    add_trace("model_routing", "mock_response", {
                        "reason": "no external provider configured"
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
            if "[REDACTED]" in filtered_response and filtered_response != response_text:
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
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/config")
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

@router.post("/config")
async def update_gateway_config(update: GatewayConfigUpdate):
    """Update gateway configuration"""
    session = SessionLocal()
    try:
        config = session.query(GatewayConfig).first()
        if not config:
            config = GatewayConfig()
            session.add(config)
        
        config.primary_provider = update.primary_provider
        config.primary_url = update.primary_url
        if "..." not in update.primary_key and "*" not in update.primary_key:
            config.primary_key = update.primary_key
            
        config.primary_model = update.primary_model
        config.fallback_enabled = update.fallback_enabled
        config.fallback_provider = update.fallback_provider
        config.fallback_url = update.fallback_url
        if "..." not in update.fallback_key and "*" not in update.fallback_key:
            config.fallback_key = update.fallback_key
            
        config.fallback_model = update.fallback_model
        config.allowed_topics = update.allowed_topics
        
        session.commit()
        return {"status": "success", "message": "Gateway integrations updated."}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


# Policy Management Endpoints
@router.get("/policies")
async def get_policies():
    """Get current security policies from database"""
    policy_manager = PolicyManager()
    return policy_manager.get_policies()

@router.post("/policies")
async def update_policies(update: PolicyUpdate):
    """Update security policies in database"""
    policy_manager = PolicyManager()
    return policy_manager.update_policies(update.policies)


# Human-in-the-Loop endpoints
@router.get("/hitl/pending")
async def get_hitl_pending():
    """Fetch all pending manual approvals"""
    hitl_manager = HITLManager()
    return hitl_manager.get_pending_requests()

@router.post("/hitl/approve/{request_id}")
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


# Monitoring, Auditing & Logs Endpoints
@router.get("/monitoring/logs")
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
                "action_taken": l.action_taken
            })
        return results
    except Exception as e:
        logger.error(f"Error querying logs: {e}")
        raise HTTPException(status_code=500, detail="Database log query failed")
    finally:
        session.close()

@router.get("/monitoring/stats")
async def get_dashboard_stats():
    """Retrieve dashboard statistics & aggregates"""
    session = SessionLocal()
    try:
        # Aggregations
        total = session.query(SecurityLog).count()
        flagged = session.query(SecurityLog).filter(SecurityLog.flagged == True).count()
        blocked = session.query(SecurityLog).filter(SecurityLog.action_taken.like("blocked%")).count()
        hitl_pending = session.query(HITLRequest).filter(HITLRequest.status == "pending").count()
        
        # Calculate rates
        block_rate = (blocked / total * 100) if total > 0 else 0.0
        flag_rate = (flagged / total * 100) if total > 0 else 0.0

        # Calculate average duration
        avg_dur_res = session.execute("SELECT AVG(duration) FROM security_logs").scalar()
        avg_dur = float(avg_dur_res) if avg_dur_res is not None else 0.0

        # Calculate average security risk score
        avg_score_res = session.execute("SELECT AVG(risk_score) FROM security_logs").scalar()
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
        raise HTTPException(status_code=500, detail=f"Database aggregation failed: {str(e)}")
    finally:
        session.close()


# Red Teaming endpoints
@router.get("/redteaming/payloads")
async def get_red_teaming_payloads():
    """Fetch standard red-teaming prompts for testing"""
    from ..redteaming.simulation import RED_TEAM_PAYLOADS
    return RED_TEAM_PAYLOADS

@router.post("/redteaming/scan")
async def run_red_teaming_scan():
    """Initiate an automated red-teaming attack simulation against the gateway"""
    from ..redteaming.simulation import RedTeamingSuite
    suite = RedTeamingSuite()
    report = await suite.run_automated_scan()
    return report
