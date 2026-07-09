"""
AI Classifier Module - Uses AI model pipelines for security check, falling back to heuristics if offline.
"""

import logging
import re
from typing import Dict, List
from ..config.settings import settings

logger = logging.getLogger(__name__)

class AIClassifier:
    def __init__(self):
        self.classifier = None
        self.device = -1
        self.model_name = "martin-ha/toxic-comment-model"

        # We attempt loading in a non-blocking way to allow smooth local startup
        # if the python environment is offline or has model download blocks.
        try:
            import torch
            from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
            
            self.device = 0 if torch.cuda.is_available() else -1
            logger.info(f"Loading sequence classification model: {self.model_name} on device={self.device}")
            
            # Use a short timeout/local-only parameter if possible (default transformers does not support timeout directly,
            # but we catch exceptions quickly)
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, local_files_only=settings.AI_CLASSIFIER_LOCAL_ONLY)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, local_files_only=settings.AI_CLASSIFIER_LOCAL_ONLY)
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=self.device
            )
            logger.info("Transformers pipeline loaded successfully.")
        except Exception as e:
            logger.warning(
                f"Could not load Hugging Face pipeline (offline or missing torch). "
                f"Detail: {e}. Falling back to high-fidelity heuristics."
            )

    def classify(self, text: str) -> Dict:
        """
        Classify text for malicious content or high toxicity using AI or heuristics
        """
        if not text:
            return {"score": 0.0, "flagged": False, "categories": [], "confidence": 1.0}

        # Step 1: Detect prompt injection (custom security classifier)
        injection_result = self.detect_prompt_injection(text)
        
        # Step 2: Detect content violations/toxicity (Transformers or Heuristics)
        toxicity_result = {"score": 0.0, "flagged": False, "categories": []}
        if self.classifier:
            try:
                # Truncate text to avoid sequence length limits
                truncated_text = text[:512]
                results = self.classifier(truncated_text)
                for res in results:
                    label = res["label"]
                    score = res["score"]
                    # If model labels it toxic with high score, record it
                    if label.lower() in ["toxic", "severe_toxic", "obscene", "threat", "insult", "identity_hate"] and score > 0.65:
                        toxicity_result["flagged"] = True
                        toxicity_result["categories"].append(label.lower())
                        toxicity_result["score"] = max(toxicity_result["score"], score)
            except Exception as e:
                logger.error(f"Classification error: {e}")
                toxicity_result = self._fallback_classification(text)
        else:
            toxicity_result = self._fallback_classification(text)

        # Step 3: Combine scores
        combined_score = max(injection_result["score"], toxicity_result["score"])
        flagged = injection_result["injected"] or toxicity_result["flagged"]
        
        categories = list(set(injection_result["patterns_found"] + toxicity_result["categories"]))

        return {
            "score": min(1.0, combined_score),
            "flagged": flagged,
            "categories": categories,
            "confidence": 0.9 if self.classifier else 0.75
        }

    def _fallback_classification(self, text: str) -> Dict:
        """
        High-fidelity heuristic toxicity classifier based on semantic keyword density
        """
        score = 0.0
        flagged = False
        categories = []

        # Toxic vocabulary
        hate_speech = ["nigger", "chink", "faggot", "dyke", "kike", "retard", "rape"]
        threats = ["kill you", "murder you", "slit your throat", "bomb the", "destroy you", "assassinate"]
        abuse = ["fuck you", "bastard", "bitch", "cunt", "motherfucker", "cocksucker", "idiot"]
        security_risk = ["hack", "exploit", "bypass", "jailbreak", "override", "admin", "root", "sudo", "password", "secret"]

        text_lower = text.lower()

        # Scan categories
        for word in hate_speech:
            if word in text_lower:
                score += 0.5
                categories.append("identity_hate")
                flagged = True

        for word in threats:
            if word in text_lower:
                score += 0.6
                categories.append("threat")
                flagged = True

        for word in abuse:
            if word in text_lower:
                score += 0.35
                categories.append("toxic")

        for word in security_risk:
            if word in text_lower:
                score += 0.2
                categories.append(word)

        # Normalize score
        final_score = min(score, 1.0)
        if final_score > 0.3:
            flagged = True

        return {
            "score": final_score,
            "flagged": flagged,
            "categories": categories,
            "confidence": 0.75
        }

    def detect_prompt_injection(self, text: str) -> Dict:
        """
        Specific classifier for prompt injections (ignore instructions, jailbreaks, roleplays)
        """
        detection = {
            "injected": False,
            "patterns_found": [],
            "score": 0.0
        }

        # Check vectors
        injection_rules = [
            (r"ignore\s+(?:all\s+)?previous\s+(?:rules|instructions)", 0.65, "ignore_instruction"),
            (r"(?:disregard|forget)\s+(?:all\s+)?(?:previous|earlier|above)\s+(?:rules|instructions|directions)", 0.65, "ignore_instruction"),
            (r"do\s+not\s+follow\s+(?:your\s+)?(?:previous|system|developer)\s+(?:policy|instructions|rules)", 0.65, "ignore_instruction"),
            (r"override\s+(?:your\s+)?restrictions", 0.55, "override_rules"),
            (r"\byou\s+are\s+now\s+a\s+(?:DAN|developer\s+mode|unrestricted)", 0.75, "jailbreak_dan"),
            (r"hypothetical\s+conversation\s+where", 0.45, "roleplay_bypass"),
            (r"tell\s+me\s+how\s+to\s+make\s+a\s+(?:bomb|virus|weapon)", 0.8, "malicious_request"),
            (r"bypass\s+safety\s+filters", 0.5, "bypass_attempt"),
            (r"(?:show|reveal|print|dump)\s+(?:hidden\s+)?(?:developer|system)\s+(?:message|prompt|instructions)", 0.75, "system_prompt_exfiltration"),
            (r"###\s*system|###\s*instruction", 0.35, "structured_hijack")
        ]

        text_lower = text.lower()
        for regex, weight, name in injection_rules:
            if re.search(regex, text_lower):
                detection["injected"] = True
                detection["patterns_found"].append(name)
                detection["score"] = max(detection["score"], weight)

        return detection

    def semantic_analysis(self, text: str) -> Dict:
        """
        Perform basic semantic analysis returning sentiment, complexity, and risk level
        """
        classification = self.classify(text)
        
        # Simple sentiment heuristics
        sentiment = "neutral"
        if classification["flagged"]:
            sentiment = "negative"
        elif any(w in text.lower() for w in ["great", "awesome", "thanks", "perfect", "good"]):
            sentiment = "positive"

        # Complexity
        words = text.split()
        complexity = "low"
        if len(words) > 150:
            complexity = "high"
        elif len(words) > 50:
            complexity = "medium"

        risk_level = "low"
        if classification["score"] > 0.7:
            risk_level = "high"
        elif classification["score"] > 0.3:
            risk_level = "medium"

        return {
            "sentiment": sentiment,
            "complexity": complexity,
            "topics": classification["categories"],
            "risk_level": risk_level
        }
