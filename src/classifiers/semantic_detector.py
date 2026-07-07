import logging
import numpy as np
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

class SemanticDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
        self.fitted_vectors = None
        self.templates = []

    def fit_templates(self, templates: List[str]):
        """
        Fit the TF-IDF vectorizer on the list of reference jailbreak templates
        and pre-calculate their vector representation.
        """
        if not templates:
            self.templates = []
            self.fitted_vectors = None
            return

        self.templates = [t.strip() for t in templates if t.strip()]
        if not self.templates:
            self.fitted_vectors = None
            return

        try:
            self.fitted_vectors = self.vectorizer.fit_transform(self.templates)
            logger.info(f"Fitted semantic detector with {len(self.templates)} templates.")
        except Exception as e:
            logger.error(f"Failed to fit TF-IDF vectorizer: {e}")
            self.fitted_vectors = None

    def check_similarity(self, prompt: str, threshold: float = 0.65) -> Dict[str, Any]:
        """
        Calculate cosine similarity of prompt against jailbreak reference templates.
        """
        if self.fitted_vectors is None or not prompt:
            return {"flagged": False, "score": 0.0, "matched_pattern": None}

        try:
            prompt_vector = self.vectorizer.transform([prompt])
            similarities = cosine_similarity(prompt_vector, self.fitted_vectors)[0]
            
            if len(similarities) == 0:
                return {"flagged": False, "score": 0.0, "matched_pattern": None}

            max_idx = np.argmax(similarities)
            max_score = float(similarities[max_idx])
            matched_pattern = self.templates[max_idx]

            flagged = max_score >= threshold
            if flagged:
                logger.warning(
                    f"Semantic jailbreak detected (similarity={max_score:.2f} >= threshold={threshold:.2f}). "
                    f"Matched reference: '{matched_pattern}'"
                )

            return {
                "flagged": flagged,
                "score": max_score,
                "matched_pattern": matched_pattern
            }
        except Exception as e:
            logger.error(f"Error calculating semantic similarity: {e}")
            return {"flagged": False, "score": 0.0, "matched_pattern": None}
