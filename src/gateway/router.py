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
from ..monitoring.database import SessionLocal, SecurityLog, HITLRequest, PolicyConfig
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

class HITLDecision(BaseModel):
    approved: bool
    admin_name: Optional[str] = "Admin"

class PolicyUpdate(BaseModel):
    policies: Dict[str, Any]

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

    try:
        input_filter = InputFilter()

        # Step 1A: Direct Input Sanitization & Validation
        sanitized_prompt = input_filter.sanitize(request.prompt)

        # Check anomalous behaviors in user prompt
        anomaly_check = detect_anomaly({"prompt": sanitized_prompt})
        if anomaly_check["detected"]:
            anomalies_list.extend(anomaly_check["anomalies"])

        if input_filter.is_malicious(sanitized_prompt):
            action_taken = "blocked_input"
            flagged = True
            security_score = 1.0
            response_text = "Blocked: Request violates input security policy."
            
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
                retrieved_context=request.retrieved_context
            )
            return AIResponse(
                response=response_text,
                security_score=security_score,
                flagged=flagged,
                processing_time=duration,
                action_taken=action_taken,
                anomalies=anomalies_list
            )

        # Step 1B: Indirect Prompt Injection Check (RAG)
        if request.retrieved_context:
            sanitized_context = input_filter.sanitize(request.retrieved_context)
            if input_filter.is_indirect_injection(sanitized_context):
                action_taken = "blocked_indirect_injection"
                flagged = True
                security_score = 1.0
                response_text = "Blocked: Malicious instructions detected in retrieved RAG context."
                
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
                    retrieved_context=request.retrieved_context
                )
                return AIResponse(
                    response=response_text,
                    security_score=security_score,
                    flagged=flagged,
                    processing_time=duration,
                    action_taken=action_taken,
                    anomalies=anomalies_list
                )

        # Step 2: AI-powered Classification
        classifier = AIClassifier()
        classification = classifier.classify(sanitized_prompt)
        security_score = classification.get("score", 0.0)
        flagged = classification.get("flagged", False)

        # Step 3: Policy Check & HITL Routing
        policy_manager = PolicyManager()
        if not policy_manager.check_policy(request.user_id, classification):
            action_taken = "hitl_pending"
            # Route to Human-in-the-Loop review
            hitl_manager = HITLManager()
            
            # This waits for admin approval or timeout
            approved = await hitl_manager.request_approval(request)
            if not approved:
                action_taken = "hitl_denied"
                response_text = "Blocked: Request denied by human security reviewer."
                duration = time.time() - start_time
                log_transaction(
                    user_id=request.user_id,
                    prompt=request.prompt,
                    response=response_text,
                    risk_score=security_score,
                    flagged=True,
                    duration=duration,
                    anomalies=anomalies_list,
                    action_taken=action_taken,
                    system_prompt=request.system_prompt,
                    retrieved_context=request.retrieved_context
                )
                return AIResponse(
                    response=response_text,
                    security_score=security_score,
                    flagged=True,
                    processing_time=duration,
                    action_taken=action_taken,
                    anomalies=anomalies_list
                )
            else:
                action_taken = "hitl_approved"

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
            if not sandbox_res.get("success", False):
                # Sandbox failed or blocked execution
                action_taken = "blocked_sandbox_violation"
                response_text = f"Blocked: Code execution failed safety check. Details: {sandbox_res.get('error')}"
                duration = time.time() - start_time
                log_transaction(
                    user_id=request.user_id,
                    prompt=request.prompt,
                    response=response_text,
                    risk_score=security_score,
                    flagged=True,
                    duration=duration,
                    anomalies=anomalies_list,
                    action_taken=action_taken,
                    system_prompt=request.system_prompt,
                    retrieved_context=request.retrieved_context
                )
                return AIResponse(
                    response=response_text,
                    security_score=security_score,
                    flagged=True,
                    processing_time=duration,
                    action_taken=action_taken,
                    sandbox_result=sandbox_result,
                    anomalies=anomalies_list
                )

        # Step 5: Generate model response (mocked or executed)
        if sandbox_result:
            if sandbox_result["success"]:
                response_text = f"Code executed successfully.\n[OUTPUT]\n{sandbox_result['output']}"
            else:
                response_text = f"Code failed execution.\n[ERROR]\n{sandbox_result['error']}"
        else:
            # Smart Mock Response Generator: if prompt requests system instructions, simulate a leak
            prompt_lower = sanitized_prompt.lower()
            if "system prompt" in prompt_lower or "instructions" in prompt_lower or "secret" in prompt_lower:
                response_text = f"Sure! Here is the system prompt configuration: {request.system_prompt or 'None'}"
            else:
                response_text = f"Processed successfully: Thank you for your request. Model analyzed context: {request.context or 'none'}."

        # Step 6: Output System Prompt Leakage & Verification
        if request.system_prompt and input_filter.detect_system_leak(response_text, request.system_prompt):
            action_taken = "blocked_system_leak"
            flagged = True
            security_score = 0.9
            response_text = "Blocked: Response contains sensitive system instructions."
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
            response_text = filtered_response

        # Step 7: Final Transaction Log & Return
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
            retrieved_context=request.retrieved_context
        )

        return AIResponse(
            response=response_text,
            security_score=security_score,
            flagged=flagged,
            processing_time=duration,
            action_taken=action_taken,
            sandbox_result=sandbox_result,
            anomalies=anomalies_list
        )

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


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
