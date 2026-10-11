import os
import json
from urllib.parse import urlparse
import pandas as pd
import joblib
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Model path hierarchy: preference for v3, fallback to earlier models
MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier_v3.pkl")
FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_v3.json")

if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier_domain_candidate_v2.pkl")
    FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_domain_candidate_v2.json")

if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier.pkl")
    FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_rebuilt.json")

# Default 21 features in exact order
DEFAULT_FEATURE_COLUMNS = [
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords", "domain_entropy", "path_entropy",
    "is_high_risk_tld", "brand_impersonation", "non_standard_port"
]

feature_columns = DEFAULT_FEATURE_COLUMNS
if os.path.exists(FEATURE_ORDER_PATH):
    try:
        with open(FEATURE_ORDER_PATH, "r", encoding="utf-8") as f:
            feature_columns = json.load(f)
    except Exception:
        pass

model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None

# Verified high-reputation domains (Top global authorities)
TRUSTED_DOMAINS = {
    "wikipedia.org", "wikimedia.org", "google.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "youtube.com",
    "mozilla.org", "python.org", "stackoverflow.com", "nytimes.com",
    "bbc.com", "reuters.com", "cloudflare.com", "nih.gov", "cisa.gov",
    "w3.org", "ietf.org", "owasp.org", "kubernetes.io", "docker.com",
    "pypi.org", "arxiv.org", "stanford.edu", "mit.edu", "harvard.edu",
    "react.dev", "nodejs.org", "cern.ch", "kernel.org"
}


def is_trusted_domain(hostname: str) -> bool:
    """Check if the hostname belongs to a known verified authority domain."""
    if not hostname:
        return False
    h = hostname.lower().strip()
    return any(h == d or h.endswith("." + d) for d in TRUSTED_DOMAINS)


def classify(url: str, threshold: float = 0.50) -> dict:
    """
    Classify a URL as Safe or Malicious using the trained Random Forest classifier
    with 21 cybersecurity features, confidence estimation, and human-readable explanations.
    """
    global model
    if model is None:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please run training first.")

    # 1. Extract 21 security features
    features = extract_features(url)

    # 2. Check authority reputation
    parsed_input = url if "://" in url else "http://" + url
    hostname = (urlparse(parsed_input).hostname or "").lower()
    trusted = is_trusted_domain(hostname)

    # 3. Align features to model expectations
    # If the loaded model expects 16 features (legacy), filter down; otherwise use all 21
    expected_cols = [c for c in feature_columns if c in features]
    if hasattr(model, "n_features_in_") and model.n_features_in_ == 16:
        expected_cols = expected_cols[:16]

    X = pd.DataFrame([features])[expected_cols]

    # 4. Model Prediction & Probabilities
    probabilities = model.predict_proba(X)[0]
    prob_malicious = float(probabilities[1])
    prob_safe = float(probabilities[0])

    # 5. Build Explainability Reasons
    reasons = []

    if features.get("brand_impersonation", 0) == 1:
        reasons.append("Brand impersonation signature detected (recognized brand in deceptive context)")

    if features.get("uses_ip", 0) == 1:
        reasons.append("Uses raw IP address instead of domain name")

    if features.get("has_at_symbol", 0) == 1:
        reasons.append("Contains '@' symbol (credential injection / open redirect technique)")

    if features.get("has_double_slash_redirect", 0) == 1:
        reasons.append("Contains '//' in URL path (open redirect attempt)")

    if features.get("is_high_risk_tld", 0) == 1:
        reasons.append("Hosted on high-risk / disposable TLD frequently abused in malware campaigns")

    if features.get("non_standard_port", 0) == 1:
        reasons.append("Explicit non-standard port specified (bypassing standard web security)")

    if features.get("is_shortened", 0) == 1:
        reasons.append("Uses URL shortening service to conceal destination")

    if features.get("has_suspicious_keywords", 0) == 1:
        reasons.append("Contains high-risk credential/phishing keywords (e.g. login, verify, wallet)")

    if features.get("domain_entropy", 0.0) > 3.9:
        reasons.append(f"High domain character randomness / entropy ({features['domain_entropy']}), possible DGA")

    if features.get("shannon_entropy", 0.0) > 4.5:
        reasons.append(f"Elevated overall URL entropy ({features['shannon_entropy']})")

    if features.get("subdomain_count", 0) > 2:
        reasons.append(f"Excessive chained subdomains ({features['subdomain_count']} subdomains)")

    if features.get("digit_ratio", 0.0) > 0.20:
        reasons.append(f"High digit ratio ({int(features['digit_ratio'] * 100)}% of URL is numeric)")

    if features.get("num_hyphens", 0) > 3:
        reasons.append(f"Multiple hyphens ({features['num_hyphens']}), characteristic of brand spoofing")

    # Final verdict calculation
    # If the domain is an authoritative trusted domain or accredited institutional TLD (.edu, .gov, .mil)
    # with no overt attack signatures (IP, @, //, brand impersonation)
    clean_signatures = (
        features.get("uses_ip", 0) == 0 and
        features.get("has_at_symbol", 0) == 0 and
        features.get("has_double_slash_redirect", 0) == 0 and
        features.get("brand_impersonation", 0) == 0
    )

    if (trusted or features.get("is_institutional_tld", 0) == 1) and clean_signatures:
        verdict = "Safe"
        confidence = max(prob_safe, 0.98)
        tag = "Verified high-reputation domain authority" if trusted else "Accredited institutional (.edu/.gov/.mil) domain"
        reasons = [f"{tag} with clean security indicators."]
    else:
        if prob_malicious >= threshold:
            verdict = "Malicious"
            confidence = prob_malicious
        else:
            verdict = "Safe"
            confidence = prob_safe

        if not reasons:
            if verdict == "Safe":
                reasons.append("Standard URL structure with no active threat indicators.")
            else:
                reasons.append("Structural anomalies detected by machine-learning behavioral profile.")

    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "prob_malicious": round(prob_malicious, 4),
        "prob_safe": round(prob_safe, 4),
        "features": features,
        "reasons": reasons,
        "model_used": os.path.basename(MODEL_PATH)
    }


def main_cli():
    sample_urls = [
        "https://google.com",
        "https://docs.python.org/3/library/math.html",
        "https://react.dev/learn",
        "https://github.com/torvalds/linux",
        "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "http://192.168.1.50:8080/login/paypal/update",
        "http://paypal-security-alert.com//verify-account?token=89234823",
        "https://g5.lu/vu39k",
        "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
        "http://www.phishing-bank.xyz/update-wallet",
    ]

    print("=" * 70)
    print(f"CYBERGUARDIAN URL CLASSIFIER ({os.path.basename(MODEL_PATH)})")
    print("=" * 70)

    for url in sample_urls:
        res = classify(url)
        badge = "[ SAFE ]     " if res["verdict"] == "Safe" else "[ MALICIOUS ]"
        print(f"\n{badge} -> {url}")
        print(f"    Confidence : {res['confidence'] * 100:.2f}% (P(Malicious)={res['prob_malicious']:.2f})")
        print("    Reasons    :")
        for r in res["reasons"]:
            print(f"      * {r}")


if __name__ == "__main__":
    main_cli()