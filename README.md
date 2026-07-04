# AI Security Gateway - Secure.AI Hub

A production-grade, highly resilient **AI Security Gateway** acting as an active reverse-proxy firewall and governance hub. It wraps around your enterprise LLM endpoints (like OpenAI or local Ollama deployments) to sanitize prompt inputs, run code inside AST-validated subprocess sandboxes, block off-topic queries, redact output PII, and handle human-in-the-loop (HITL) approval states.

---

## Key Capabilities (OWASP LLM Top 10 Aligned)

*   **Resilient Fallback LLM Routing (Portkey Standard)**: Supports dynamic proxying to a Primary LLM. If the primary endpoint fails, is rate-limited, or times out, the gateway automatically failovers requests to a configured backup LLM or local simulated fallback, ensuring zero service disruption.
*   **Conversational Topic-Lock Rails (NVIDIA NeMo Standard)**: Restricts conversations to authorized business domains (e.g. `billing, support, account`) by detecting semantic drift, and automatically blocks irrelevant requests (such as asking a banking assistant to write code).
*   **RAG Context Isolation & Indirect prompt injection Check (LLM01)**: Separates requests into direct prompts and retrieved contexts, scanning context blocks separately to detect injection hijacks hidden in scraped web data.
*   **AST Code Sandbox Execution**: Compiles Python scripts inside a static AST parsing wrapper that scans for dangerous calls (like imports of `os`, `sys`, `subprocess`, or file manipulation scripts) and executes safe scripts in isolated, timed subprocesses.
*   **System Prompt Leakage Guard (LLM02)**: Prevents disclosure of confidential system instructions. If the model output reveals a phrase or word overlap ratio (exceeding a 35% threshold) with the system configuration, the gateway automatically blocks the response.
*   **PII & Token Redaction Scrubber (LLM06)**: An outbound output redactor that identifies and redacts credit card numbers, email addresses, phone numbers, Google Cloud/AWS keys, and OpenAI API tokens in real-time.
*   **Human-In-The-Loop SQLite Orchestrator**: Suspends high-risk queries in a local transactional database queue. Admins can view request contexts in a SPA dashboard to manually authorize or deny execution.
*   **Adversarial Red-Teaming Scanner**: Features a built-in audit registry containing 13 simulation attack vectors (like jailbreaks, DAN roleplay, and obfuscated shell instructions) to test and report on gateway filter posture.

---

## Technology Stack & Architecture

*   **Backend Core**: FastAPI (Asynchronous framework)
*   **Database**: SQLAlchemy + scoped SQLite (for state tracking of policies, logs, and HITL approvals)
*   **AI Classifiers**: Hugging Face seq-classifier pipeline (`martin-ha/toxic-comment-model` with lexicon-heuristics offline fallbacks)
*   **Frontend**: Vanilla CSS + Javascript SPA served dynamically on `/static`

```
  [ Client Request ] ──► [ Topic-Lock & Input Filters ] ──► [ AI Toxicity Classifier ]
                                                                  │
  ┌───────────────────────────────────────────────────────────────▼
  ▼
  [ Access Policy Rules ] ──► [ Suspended? ] ──► ( HITL SQLite Queue Admin Dashboard )
                                   │
  ┌────────────────────────────────▼
  ▼
  [ Python AST Sandbox ] ──► [ Outbound LLM Proxy (Attempts Primary -> Failover Secondary) ]
                                   │
  ┌────────────────────────────────▼
  ▼
  [ System Leakage Guard & PII Redactor ] ──► [ Clean Response Returned ]
```

---

## Installation & Setup

### Prerequisites
*   Python 3.10.x (Recommended)
*   Node.js v20.x (For local package scripts)

### Installation Steps
1. Clone the repository to your workspace.
2. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the gateway server:
    ```bash
    python run.py
    ```
4. Access the SPA Governance Dashboard:
   - Dashboard: [http://localhost:8000/](http://localhost:8000/)
   - Interactive Swagger API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Core API Endpoints

### 1. Process Queries
*   **POST** `/api/v1/process`
*   **Request Payload**:
    ```json
    {
      "prompt": "User query input here",
      "system_prompt": "You are a customer assistant. Secret key is 9982.",
      "retrieved_context": "Context retrieved from database / RAG search.",
      "user_id": "client_user_1",
      "execute_code": false
    }
    ```

### 2. Manage Integrations (Outbound Proxy)
*   **GET** `/api/v1/config` - Retrieve current primary/fallback configurations (with masked API keys).
*   **POST** `/api/v1/config` - Update provider, API url, credentials, and allowed topic filters.

### 3. Policy Controls
*   **GET** `/api/v1/policies` - Retrieve rules for input validation, content filtering thresholds, and rate limits.
*   **POST** `/api/v1/policies` - Save configuration rules.

### 4. Human-In-The-Loop Reviews
*   **GET** `/api/v1/hitl/pending` - Fetch requests suspended for review.
*   **POST** `/api/v1/hitl/approve/{request_id}` - Send approval/denial command.

---

## Verification & Testing

Verify code components and schema persistence layers:
```bash
pytest tests/
```
To run simulated red-team checks, navigate to the **Red-Teaming** section on the SPA dashboard interface and click **Launch Security Audit**.

---

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
