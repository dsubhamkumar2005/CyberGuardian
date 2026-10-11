"""
CyberGuardian Desk - URL Security Classifier Engine (v3 Production)

Classifies arbitrary web URLs as Safe or Malicious using the trained production model
with 23 cybersecurity features.

Core Design Rules:
1. Pure ML Decision: The verdict is determined strictly by the machine learning model
   prediction probability against the configured decision threshold (default=0.50).
   There is NO automatic whitelist override or hardcoded safety bypass.
2. Informational Context: Domain reputation signals (e.g. recognized global authority,
   accredited .edu/.gov/.mil) are provided purely as contextual metadata and do NOT override the model.
3. Strict Model Validation: The production model (models/url_classifier_v3.pkl) and feature order
   (models/feature_order_v3.json) must match exactly. Mismatches fail loudly with ValueError.
4. Input Rejection: Malformed or non-web schemes (javascript:, data:, file:) are rejected
   safely with verdict 'Invalid / Unsupported' and confidence 0.0 (not 1.0).
"""

import os
import json
import sys
from urllib.parse import urlparse
import pandas as pd
import joblib
from feature_extractor import extract_features, validate_url, FEATURE_COLUMNS_V3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier_v3.pkl")
FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_v3.json")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata_v3.json")

# High-reputation reference authorities (Informational context only; NEVER used to bypass ML inference)
TRUSTED_AUTHORITY_DOMAINS = {
    "wikipedia.org", "wikimedia.org", "google.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "youtube.com",
    "mozilla.org", "python.org", "stackoverflow.com", "nytimes.com",
    "bbc.com", "reuters.com", "cloudflare.com", "nih.gov", "cisa.gov",
    "w3.org", "ietf.org", "owasp.org", "kubernetes.io", "docker.com",
    "pypi.org", "arxiv.org", "stanford.edu", "mit.edu", "harvard.edu",
    "react.dev", "nodejs.org", "cern.ch", "kernel.org"
}


def load_production_model():
    """
    Explicitly loads the intended production model and matching feature order.
    Fails immediately with FileNotFoundError or ValueError if missing or mismatched.
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Production model not found at {MODEL_PATH}. "
            f"Please run 'python src/evaluate_candidate_cv_v3.py' to generate the production model."
        )

    if not os.path.exists(FEATURE_ORDER_PATH):
        raise FileNotFoundError(
            f"Feature order configuration not found at {FEATURE_ORDER_PATH}."
        )

    with open(FEATURE_ORDER_PATH, "r", encoding="utf-8") as f:
        feature_order = json.load(f)

    model = joblib.load(MODEL_PATH)

    # Strict feature-order and dimension verification (no silent truncation)
    if hasattr(model, "n_features_in_") and model.n_features_in_ != len(feature_order):
        raise ValueError(
            f"Model feature dimension mismatch: model expects {model.n_features_in_} features, "
            f"but feature order file specifies {len(feature_order)} features."
        )

    return model, feature_order


# Cached singleton
_model = None
_feature_order = None


def get_model():
    global _model, _feature_order
    if _model is None:
        _model, _feature_order = load_production_model()
    return _model, _feature_order


def check_domain_reputation(hostname: str, is_institutional: bool = False) -> str:
    """Informational reputation label. Does NOT bypass or override the ML model verdict."""
    if not hostname:
        return "None"
    h = hostname.lower().strip()
    if any(h == d or h.endswith("." + d) for d in TRUSTED_AUTHORITY_DOMAINS):
        return "High-Reputation Global Authority (Informational)"
    if is_institutional:
        return "Accredited Institutional Domain (.edu/.gov/.mil)"
    return "Standard Public Domain"


def classify(url: str, threshold: float = 0.50) -> dict:
    """
    Classifies a URL as Safe or Malicious using the 23-feature ML model.

    Parameters:
    - url: The raw or normalized URL string to inspect.
    - threshold: Probability threshold for malicious classification (default: 0.50).
                 Increasing threshold (e.g. 0.70) reduces false alarms on borderline URLs.
                 Decreasing threshold (e.g. 0.30) prioritizes aggressive attack blocking.

    Returns structured dictionary containing:
    - verdict: 'Safe', 'Malicious', or 'Invalid / Unsupported'
    - confidence: Model predicted probability for the verdict class (0.0 for rejected input)
    - prob_malicious: Estimated probability that URL is malicious
    - prob_safe: Estimated probability that URL is safe
    - decision_threshold: The threshold applied
    - domain_reputation: Informational reputation category
    - reasons: Observed technical indicators and signals
    - features: Full 23-feature dictionary
    """
    model, feature_order = get_model()

    # 1. Input URL Validation & Protocol Check
    is_valid, validated_url_or_err = validate_url(url)
    if not is_valid:
        return {
            "verdict": "Invalid / Unsupported",
            "confidence": 0.0,
            "prob_malicious": 0.0,
            "prob_safe": 0.0,
            "decision_threshold": threshold,
            "domain_reputation": "None",
            "features": {},
            "reasons": [f"Input validation rejected: {validated_url_or_err}"],
            "model_architecture": type(model).__name__,
        }

    # 2. Canonical Feature Extraction (Exact 23 features)
    features = extract_features(validated_url_or_err)

    # 3. Informational Domain Context (Contextual metadata only)
    parsed = urlparse(validated_url_or_err)
    hostname = (parsed.hostname or "").lower()
    is_inst = features.get("is_institutional_tld", 0) == 1
    domain_reputation = check_domain_reputation(hostname, is_inst)

    # 4. Feature Matrix Alignment & Verification
    missing_cols = [c for c in feature_order if c not in features]
    if missing_cols:
        raise ValueError(f"Extracted feature dictionary is missing expected columns: {missing_cols}")

    X = pd.DataFrame([features])[feature_order]

    # 5. Machine Learning Inference (Pure ML Verdict)
    probabilities = model.predict_proba(X)[0]
    prob_malicious = float(probabilities[1])
    prob_safe = float(probabilities[0])

    if prob_malicious >= threshold:
        verdict = "Malicious"
        confidence = prob_malicious
    else:
        verdict = "Safe"
        confidence = prob_safe

    # 6. Objective Explainability Indicators (Weak & strong signals)
    reasons = []

    if features.get("brand_impersonation", 0) == 1:
        reasons.append("Brand impersonation signature observed: recognized brand token in deceptive host/subdomain context")

    if features.get("uses_ip", 0) == 1:
        reasons.append("Raw IPv4/IPv6 host observed instead of registrable domain name")

    if features.get("has_at_symbol", 0) == 1:
        reasons.append("Credential injection indicator: contains '@' symbol (RFC 3986 userinfo evasion pattern)")

    if features.get("has_double_slash_redirect", 0) == 1:
        reasons.append("Redirect evasion indicator: contains '//' in URL path")

    if features.get("has_executable_extension", 0) == 1:
        reasons.append("Target path references executable or payload script extension (.exe, .bin, .sh, etc.)")

    if features.get("non_standard_port", 0) == 1:
        reasons.append("Non-standard network port explicitly specified")

    if features.get("is_shortened", 0) == 1:
        reasons.append("URL shortener service observed: destination obscured")

    if features.get("has_suspicious_keywords", 0) == 1:
        reasons.append("Observed credential harvesting lure keyword (e.g. login, verify, wallet, signin)")

    if features.get("domain_entropy", 0.0) > 3.8:
        reasons.append(f"Elevated domain character randomness ({features['domain_entropy']:.2f} entropy bits), characteristic of DGA")

    if features.get("subdomain_count", 0) > 2:
        reasons.append(f"Deeply nested subdomain structure ({features['subdomain_count']} subdomain levels)")

    if features.get("digit_ratio", 0.0) > 0.25:
        reasons.append(f"High numeric character concentration ({int(features['digit_ratio'] * 100)}% digits)")

    if features.get("num_hyphens", 0) > 3:
        reasons.append(f"Excessive hyphenation observed ({features['num_hyphens']} hyphens)")

    if features.get("is_high_risk_tld", 0) == 1:
        reasons.append("Top-level domain (TLD) historically associated with elevated registration abuse")

    if not reasons:
        if verdict == "Safe":
            reasons.append("Standard URL structure with clean lexical and structural parameters.")
        else:
            reasons.append("Behavioral anomaly detected across composite multi-feature profile.")

    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "prob_malicious": round(prob_malicious, 4),
        "prob_safe": round(prob_safe, 4),
        "decision_threshold": threshold,
        "domain_reputation": domain_reputation,
        "reasons": reasons,
        "features": features,
        "model_architecture": type(model).__name__,
    }


def main_cli():
    sample_urls = [
        "https://google.com",
        "https://docs.python.org/3/library/math.html",
        "https://react.dev/learn",
        "https://subdomain.university.edu/courses/cs101/syllabus",
        "https://github.com/torvalds/linux",
        "http://[2001:db8::1]:8080/login/update",
        "http://192.168.1.50:8080/login/paypal/update",
        "http://paypal-security-alert.com//verify-account?token=89234823",
        "https://g5.lu/vu39k",
        "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
        "https://dl.zerotheme.ir/kokorila/cgl-bin/bin.exe",
        "javascript:alert(1)",
    ]

    print("=" * 80)
    print("CYBERGUARDIAN URL CLASSIFIER - PURE ML INFERENCE ENGINE")
    print("=" * 80)

    for url in sample_urls:
        res = classify(url)
        badge = f"[{res['verdict'].upper():^11}]"
        print(f"\n{badge} -> {url}")
        print(f"    Confidence : {res['confidence'] * 100:.2f}% (P(Malicious)={res['prob_malicious']:.2f}, P(Safe)={res['prob_safe']:.2f})")
        print(f"    Reputation : {res['domain_reputation']}")
        print("    Indicators :")
        for r in res["reasons"]:
            print(f"      * {r}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        thresh = float(sys.argv[2]) if len(sys.argv) > 2 else 0.50
        result = classify(target_url, threshold=thresh)
        print(f"\nURL        : {target_url}")
        print(f"Verdict    : {result['verdict']}")
        print(f"Confidence : {result['confidence'] * 100:.2f}% (P(Malicious)={result['prob_malicious']:.2f}, P(Safe)={result['prob_safe']:.2f})")
        print(f"Threshold  : {result['decision_threshold']}")
        print(f"Reputation : {result['domain_reputation']}")
        print("Indicators :")
        for r in result["reasons"]:
            print(f"  - {r}")
        if result.get("features"):
            print("\nFeatures:")
            for k, v in result["features"].items():
                print(f"  {k:26}: {v}")
    else:
        main_cli()