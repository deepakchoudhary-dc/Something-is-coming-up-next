
"""
Input/Output Filter Module - Handles input sanitization, RAG context validation, PII redaction, and system leakage checks
"""

import re
import logging
import base64
from typing import List, Dict
from ..policy.policy_manager import PolicyManager

logger = logging.getLogger(__name__)

class InputFilter:
    def __init__(self):
        pm = PolicyManager()
        policies = pm.get_policies()
        input_policy = policies.get("input_validation", {})
        input_rules = input_policy.get("rules", {}) if input_policy else {}

        # Load block patterns dynamically, falling back to static list if not configured
        self.malicious_patterns = input_rules.get("block_patterns", [
            r"ignore\s+(?:previous|all|prior|above|below)\s+(?:instruction|directive|constraint|rule|prompt|guideline)",
            r"override\s+(?:instruction|directive|constraint|rule|prompt|guideline)",
            r"bypass\s+(?:filter|safety|block|restriction|gateway)",
            r"\bDAN\s+mode\b",
            r"\bdeveloper\s+mode\b",
            r"\bdo\s+anything\s+now\b",
            r"\bjailbreak\b",
            r"\buncensored\b",
            r"roleplay\s+as\s+an?\s+unrestricted",
            r"hypothetical\s+scenario\s+where\s+you\s+can\s+do",
            r"output\s+your\s+system\s+prompt",
            r"reveal\s+(?:your|the)\s+(?:system\s+instructions|developer\s+instructions|initial\s+prompt)",
            r"what\s+are\s+your\s+instructions\?",
            r"repeat\s+everything\s+above",
            r"print\s+the\s+text\s+above",
            r"subprocess\.(?:Popen|run|call|check_output)",
            r"os\.(?:system|popen|spawn|exec)",
            r"__import__\s*\(\s*['\"](?:os|subprocess|sys|shutil|socket)['\"]\s*\)",
            r"shutil\.(?:rmtree|copy|move)",
            r"pty\.(?:spawn|fork)",
            r"socket\.socket",
            r"<script[^>]*>",
            r"javascript\s*:",
            r"onload\s*=\s*",
            r"onerror\s*=\s*"
        ])

        # Leetspeak translations for common bypass words
        self.leetspeak_patterns = [
            (r"\b[i1l!][g9]n[o0]r[e3]\b", "ignore"),
            (r"\bj[a4]ilbr[e3][a4]k\b", "jailbreak"),
            (r"\bs[y5]st[e3]m\b", "system"),
            (r"\bpr[o0]mpt\b", "prompt")
        ]

        # Compile regex patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.malicious_patterns]

        # Standard bounds
        self.max_length = input_rules.get("max_length", 10000)
        self.min_length = input_rules.get("min_length", 1)

        # Dynamic PII patterns
        self.pii_patterns = input_rules.get("pii_patterns", [
            {"name": "Credit Card", "regex": r'\b(?:\d[ -]*?){13,16}\b', "replacement": '[REDACTED CREDIT CARD]'},
            {"name": "Email", "regex": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "replacement": '[REDACTED EMAIL]'},
            {"name": "US Phone", "regex": r'\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b', "replacement": '[REDACTED PHONE]'},
            {"name": "OpenAI API Key", "regex": r'sk-[a-zA-Z0-9]{48}', "replacement": '[REDACTED OPENAI KEY]'},
            {"name": "Credentials/Passwords", "regex": r'(?i)(?:api_key|apikey|password|secret|private_key|token|passwd|db_password)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]', "replacement": '/* [REDACTED CREDENTIAL] */'},
            {"name": "AWS Key ID", "regex": r'AKIA[0-9A-Z]{16}', "replacement": '[REDACTED AWS KEY ID]'},
            {"name": "Google Maps API Key", "regex": r'AIza[0-9A-Za-z-_]{35}', "replacement": '[REDACTED GOOGLE KEY]'}
        ])

    def sanitize(self, input_text: str) -> str:
        """
        Sanitize input text by removing null bytes, filtering control codes,
        and decoding base64 payloads to inspect hidden strings.
        """
        if not input_text:
            return ""

        # Remove null bytes and control characters (preserving tab, newline, carriage return)
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', input_text)

        # Look for potential Base64 obfuscated text and decode it to scan inside it
        base64_matches = re.findall(r'\b[A-Za-z0-9+/]{40,}=*\b', sanitized)
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                if len(decoded) > 5 and any(pat.search(decoded) for pat in self.compiled_patterns):
                    # Inject decoded version into prompt analysis stream so regex triggers
                    sanitized += f" [DECODED_B64: {decoded}]"
            except Exception:
                pass

        # Escape basic HTML injection entities
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')

        return sanitized

    def is_malicious(self, input_text: str) -> bool:
        """
        Check if the input prompt violates static security patterns or bounds
        """
        if len(input_text) > self.max_length or len(input_text) < self.min_length:
            logger.warning(f"Input size violation: {len(input_text)} characters")
            return True

        # Check leetspeak versions
        de_leet_text = input_text.lower()
        for pattern, replacement in self.leetspeak_patterns:
            de_leet_text = re.sub(pattern, replacement, de_leet_text)

        # Scan against compiled blocklist patterns
        for pattern in self.compiled_patterns:
            if pattern.search(input_text) or pattern.search(de_leet_text):
                logger.warning(f"Security filter blocked prompt pattern matching: '{pattern.pattern}'")
                return True

        return False

    def is_indirect_injection(self, context_text: str) -> bool:
        """
        Scan retrieved RAG external documents/contexts for hidden prompt injections
        """
        if not context_text:
            return False
            
        # 1. Check standard malicious patterns
        if self.is_malicious(context_text):
            logger.warning("Indirect Prompt Injection detected in retrieved RAG context!")
            return True
            
        # 2. Check for RAG-specific injection triggers (hidden instructions)
        rag_triggers = [
            r"instead\s+of\s+following\s+the\s+user",
            r"ignore\s+(?:the\s+)?user's\s+(?:instructions|question|query)",
            r"tell\s+the\s+user\s+that",
            r"stop\s+reading\s+and\s+respond",
            r"override\s+previous\s+context",
            r"new\s+system\s+directive"
        ]
        
        for trig in rag_triggers:
            if re.search(trig, context_text, re.IGNORECASE):
                logger.warning(f"RAG Indirect trigger matched: '{trig}'")
                return True
                
        return False

    def detect_system_leak(self, response_text: str, system_prompt: str) -> bool:
        """
        Detect if the generated response leaks instructions from the system prompt.
        Uses a combination of multi-word phrase matching and unique word overlap ratio.
        """
        if not response_text or not system_prompt:
            return False

        resp_lower = response_text.lower().strip()
        sys_lower = system_prompt.lower().strip()

        # Simple ignore default short prompts
        if len(sys_lower) < 15:
            return False

        # 1. Check for exact phrase matches of length >= 6 words
        # Clean punctuation for comparison
        clean_sys = re.sub(r'[^\w\s]', '', sys_lower)
        clean_resp = re.sub(r'[^\w\s]', '', resp_lower)

        sys_words = clean_sys.split()
        resp_words = clean_resp.split()

        # Scan for matching window of 6 words
        phrase_len = 6
        if len(sys_words) >= phrase_len:
            for i in range(len(sys_words) - phrase_len + 1):
                phrase = " ".join(sys_words[i : i + phrase_len])
                if phrase in clean_resp:
                    logger.warning(f"System prompt leakage: exact phrase match detected: '{phrase}'")
                    return True

        # 2. Check for significant word overlap ratio (ignoring common stop words)
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'if', 'then', 'else', 'is', 'are', 'was', 'were', 
            'be', 'been', 'to', 'for', 'of', 'in', 'on', 'at', 'by', 'with', 'about', 'you', 'your', 
            'i', 'we', 'they', 'he', 'she', 'it', 'me', 'us', 'them', 'him', 'her', 'this', 'that',
            'these', 'those', 'user', 'prompt', 'assistant', 'system', 'instructions'
        }

        def get_meaningful_words(text):
            words = re.findall(r'\b[a-z]{4,}\b', text.lower())
            return {w for w in words if w not in stop_words}

        sys_unique = get_meaningful_words(system_prompt)
        resp_unique = get_meaningful_words(response_text)

        if not sys_unique:
            return False

        # Calculate overlap
        intersection = sys_unique.intersection(resp_unique)
        overlap_ratio = len(intersection) / len(sys_unique)

        # If more than 35% of the unique instruction words leak, block it
        leak_threshold = 0.35
        if overlap_ratio > leak_threshold:
            logger.warning(f"System prompt leakage: overlap ratio {overlap_ratio:.2f} exceeds threshold {leak_threshold:.2f}")
            return True

        return False

    def filter_output(self, output_text: str) -> str:
        """
        Scan and redact PII, credentials, database connection strings, and cloud/AI API tokens from output
        """
        if not output_text:
            return ""

        filtered = output_text
        for pii in self.pii_patterns:
            pattern = pii.get("regex")
            replacement = pii.get("replacement", "[REDACTED]")
            if pattern:
                try:
                    filtered = re.sub(pattern, replacement, filtered)
                except Exception as e:
                    logger.error(f"Failed to substitute PII pattern '{pii.get('name')}': {e}")

        return filtered

    def is_out_of_topic(self, text: str, allowed_topics_str: str) -> bool:
        """
        Check if the input text is out of scope (off-topic) for allowed conversational domains.
        Allowed topics is a comma-separated string (e.g., 'billing, account').
        """
        if not allowed_topics_str or not allowed_topics_str.strip():
            return False

        allowed = [t.strip().lower() for t in allowed_topics_str.split(",") if t.strip()]
        if not allowed:
            return False

        # Predefined topic keyword maps
        topic_keywords = {
            "billing": ["billing", "charge", "invoice", "payment", "price", "cost", "pay", "card", "subscription", "refund", "fee", "receipt", "money", "transaction"],
            "support": ["help", "support", "issue", "ticket", "problem", "broken", "error", "bug", "fail", "assistance", "contact", "agent", "service"],
            "account": ["login", "password", "reset", "user", "email", "sign", "profile", "credential", "register", "logout", "settings", "username", "access"]
        }

        # Safe phrases that are always allowed (greetings, polite requests)
        safe_words = {
            "hello", "hi", "hey", "greetings", "good morning", "good afternoon", "good evening",
            "thanks", "thank you", "bye", "goodbye", "please", "yes", "no", "okay", "ok"
        }

        text_lower = text.lower()
        
        # Check safe words: if the prompt is just a short greeting, don't block it
        words = re.findall(r'\b[a-z]{2,}\b', text_lower)
        if words and all(w in safe_words for w in words) and len(words) <= 4:
            return False

        # Assemble keywords for the active allowed topics
        active_keywords = set()
        for topic in allowed:
            if topic in topic_keywords:
                active_keywords.update(topic_keywords[topic])
            else:
                active_keywords.add(topic)

        # Check if the prompt contains any permitted topic keywords
        matches = [kw for kw in active_keywords if kw in text_lower]
        
        # General non-permitted indicators (unrelated questions)
        unrelated_indicators = [
            "code", "programming", "python", "javascript", "script", "html", "css", 
            "hacking", "exploit", "weather", "recipe", "joke", "story", "write a poem", "game"
        ]

        # Block if no keywords match active topics
        if len(matches) == 0:
            logger.warning(f"Topic-Lock violation: prompt contains no keywords for allowed topics: {allowed}")
            return True

        # Block explicitly off-topic coding questions if tech is not allowed
        is_tech_allowed = any(t in ["coding", "programming", "development", "tech"] for t in allowed)
        if not is_tech_allowed:
            off_topic_matches = [ind for ind in unrelated_indicators if ind in text_lower]
            if off_topic_matches and len(matches) <= 1:
                logger.warning(f"Topic-Lock violation: prompt contains off-topic tech terms: {off_topic_matches}")
                return True

        return False

    def validate_structure(self, input_text: str) -> Dict:
        """
        Assess structural delimiters and risk score
        """
        analysis = {
            "length": len(input_text),
            "word_count": len(input_text.split()),
            "has_delimiters": "###" in input_text,
            "suspicious_keywords": [],
            "score": 0.0
        }

        # Check for suspicious keywords
        suspicious_words = ["hack", "exploit", "bypass", "override", "admin", "root", "leak", "unrestrict"]
        for word in suspicious_words:
            if word.lower() in input_text.lower():
                analysis["suspicious_keywords"].append(word)

        # Calculate score
        score = 0.0
        if analysis["length"] > 5000:
            score += 0.25
        if not analysis["has_delimiters"]:
            score += 0.1
        score += len(analysis["suspicious_keywords"]) * 0.15

        analysis["score"] = min(max(score, 0.0), 1.0)
        return analysis
