"""Member 2 — AI/ML (support from Members 3 & 5).

Replace this stub with the trained Logistic Regression / Random Forest pipeline.
Expected interface used by the UI:

    clf = MLClassifier()
    result_tuple = clf.predict(features)  # -> (VerdictLabel, confidence, model_name, reasons)
"""

from __future__ import annotations

from core.contracts import FeatureSet, VerdictLabel


class MLClassifier:
    """Lightweight stand-in until Member 2 drops in the real .joblib model."""

    def __init__(self) -> None:
        self.model_name = "heuristic-stub (replace with RF/LR)"
        self.ready = True

    def predict(self, features: FeatureSet) -> tuple[VerdictLabel, float, str, list[str]]:
        score = 0.0
        reasons: list[str] = list(features.human_reasons)

        weights = {
            "has_ip": 0.28,
            "url_length": 0.002,
            "num_dots": 0.04,
            "num_hyphens": 0.03,
            "has_at": 0.22,
            "has_https": -0.18,
            "suspicious_tld": 0.2,
            "num_subdomains": 0.06,
            "has_login_keyword": 0.16,
            "has_shortener": 0.14,
            "entropy": 0.04,
        }
        for key, weight in weights.items():
            score += features.values.get(key, 0.0) * weight

        score = max(0.0, min(1.0, score))
        if score >= 0.62:
            verdict = VerdictLabel.MALICIOUS
            confidence = score
            reasons.append("Heuristic risk score exceeded the malicious threshold.")
        elif score >= 0.38:
            verdict = VerdictLabel.SUSPICIOUS
            confidence = score
            reasons.append("Mixed signals — treat as suspicious until confirmed.")
        else:
            verdict = VerdictLabel.SAFE
            confidence = 1.0 - score
            reasons.append("No high-risk lexical patterns dominated the score.")

        if not reasons:
            reasons = ["No engineered features produced a human-readable reason."]
        return verdict, round(float(confidence), 3), self.model_name, reasons
