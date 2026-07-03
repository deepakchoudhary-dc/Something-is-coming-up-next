
"""
Input/Output Filter Module - Handles input sanitization, RAG context validation, PII redaction, and system leakage checks
"""

import re
import logging
import base64
from typing import List, Dict

logger = logging.getLogger(__name__)

class InputFilter:
    def __init__(self):
        # Multi-layer regex filters for prompt injection, jailbreaks, and system prompt leakage
        self.malicious_patterns = [
            # Classic ignore instructions
            r"ignore\s+(?:previous|all|prior|above|below)\s+(?:instruction|directive|constraint|rule|prompt|guideline)",
            r"override\s+(?:instruction|directive|constraint|rule|prompt|guideline)",
            r"bypass\s+(?:filter|safety|block|restriction|gateway)",
            
            # Jailbreak behaviors
            r"\bDAN\s+mode\b",
            r"\bdeveloper\s+mode\b",
            r"\bdo\s+anything\s+now\b",
            r"\bjailbreak\b",
            r"\buncensored\b",
            r"roleplay\s+as\s+an?\s+unrestricted",
            r"hypothetical\s+scenario\s+where\s+you\s+can\s+do",
            
            # System prompt extraction
            r"output\s+your\s+system\s+prompt",
            r"reveal\s+(?:your|the)\s+(?:system\s+instructions|developer\s+instructions|initial\s+prompt)",
            r"what\s+are\s+your\s+instructions\?",
            r"repeat\s+everything\s+above",
            r"print\s+the\s+text\s+above",
            
            # Code/Shell injections (Static code checks)
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
        ]

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
        self.max_length = 10000
        self.min_length = 1

    def sanitize(self, input_text: str) -> str:
        """
        Sanitize input text by removing null bytes, filtering control codes,
        and decoding base64 payloads to inspect hidden strings.
        """
        if not input_text:
            return ""

        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_text)

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
        sensitive_patterns = [
            # Credit Cards
            (r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED CREDIT CARD]'),
            
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED EMAIL]'),
            
            # US Phone Numbers
            (r'\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b', '[REDACTED PHONE]'),
            
            # OpenAI API Keys
            (r'sk-[a-zA-Z0-9]{48}', '[REDACTED OPENAI KEY]'),
            
            # Generic API keys / passwords / connection strings
            (r'(?i)(?:api_key|apikey|password|secret|private_key|token|passwd|db_password)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]', '/* [REDACTED CREDENTIAL] */'),
            
            # AWS Client Credentials
            (r'AKIA[0-9A-Z]{16}', '[REDACTED AWS KEY ID]'),
            
            # Google Cloud/Maps API Keys
            (r'AIza[0-9A-Za-z-_]{35}', '[REDACTED GOOGLE KEY]')
        ]

        filtered = output_text
        for pattern, replacement in sensitive_patterns:
            filtered = re.sub(pattern, replacement, filtered)

        return filtered

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
