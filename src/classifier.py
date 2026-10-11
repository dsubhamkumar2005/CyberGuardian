import os
import json
from urllib.parse import urlparse
import pandas as pd
import joblib
from feature_extractor import extract_features, validate_url, FEATURE_COLUMNS_V3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier_v3.pkl")
FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_v3.json")

# Fallback hierarchy
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier_domain_candidate_v2.pkl")
    FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_domain_candidate_v2.json")

if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier.pkl")
    FEATURE_ORDER_PATH = os.path.join(MODELS_DIR, "feature_order_rebuilt.json")

feature_columns = FEATURE_COLUMNS_V3
if os.path.exists(FEATURE_ORDER_PATH):
    try:
        with open(FEATURE_ORDER_PATH, "r", encoding="utf-8") as f:
            feature_columns = json.load(f)
    except Exception:
        feature_columns = FEATURE_COLUMNS_V3

model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None

# Verified high-reputation authority domains (Informational context only; NOT used to bypass ML model)
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
    """Informational check whether hostname matches a verified high-reputation domain."""
    if not hostname:
        return False
    h = hostname.lower().strip()
    return any(h == d or h.endswith("." + d) for d in TRUSTED_DOMAINS)


def classify(url: str, threshold: float = 0.50) -> dict:
    """
    Classify a URL as Safe or Malicious using the trained Random Forest classifier
    with 23 cybersecurity features.
    
    NOTE: The classification verdict is determined SOLELY by the trained machine learning model
    probability and calibrated threshold. There is NO hardcoded safe override or automatic whitelist bypass.
    """
    global model
    if model is None:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please run training first.")

    # 1. Input URL Validation & Protocol Check
    is_valid, validated_url_or_err = validate_url(url)
    if not is_valid:
        return {
            "verdict": "Invalid / Unsupported",
            "confidence": 1.0,
            "prob_malicious": 0.0,
            "prob_safe": 0.0,
            "features": {},
            "reasons": [f"URL Validation Failed: {validated_url_or_err}"],
            "domain_reputation": "None",
            "model_used": "None"
        }

    # 2. Feature Extraction (All 23 features)
    features = extract_features(validated_url_or_err)

    # 3. Informational Context (Not used to override model decisions)
    parsed = urlparse(validated_url_or_err)
    hostname = (parsed.hostname or "").lower()
    is_trusted = is_trusted_domain(hostname)
    is_inst = features.get("is_institutional_tld", 0) == 1

    if is_trusted:
        domain_reputation = "High-Reputation Global Authority (Informational)"
    elif is_inst:
        domain_reputation = "Accredited Institutional Domain (.edu/.gov/.mil)"
    else:
        domain_reputation = "Standard Public Domain"

    # 4. Feature Matrix Alignment
    expected_cols = [c for c in feature_columns if c in features]
    if hasattr(model, "n_features_in_") and model.n_features_in_ != len(expected_cols):
        expected_cols = expected_cols[:model.n_features_in_]

    X = pd.DataFrame([features])[expected_cols]

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

    # 6. Objective Explainability Reasons
    reasons = []

    if features.get("brand_impersonation", 0) == 1:
        reasons.append("Brand impersonation signature detected (recognized brand in deceptive host/subdomain context)")

    if features.get("uses_ip", 0) == 1:
        reasons.append("Uses raw IPv4/IPv6 address instead of registrable domain name")

    if features.get("has_at_symbol", 0) == 1:
        reasons.append("Contains '@' symbol (credential injection / open redirect technique)")

    if features.get("has_double_slash_redirect", 0) == 1:
        reasons.append("Contains '//' in URL path (open redirect evasion attempt)")

    if features.get("has_executable_extension", 0) == 1:
        reasons.append("Path targets direct executable or script payload (.exe, .bin, .sh, etc.)")

    if features.get("non_standard_port", 0) == 1:
        reasons.append("Explicit non-standard network port specified")

    if features.get("is_shortened", 0) == 1:
        reasons.append("Uses URL shortening service to conceal destination")

    if features.get("has_suspicious_keywords", 0) == 1:
        reasons.append("Contains tokenized credential harvesting keywords (e.g. login, verify, wallet)")

    if features.get("domain_entropy", 0.0) > 3.8:
        reasons.append(f"Elevated domain character randomness / entropy ({features['domain_entropy']}), possible DGA pattern")

    if features.get("subdomain_count", 0) > 2:
        reasons.append(f"Deeply nested subdomains ({features['subdomain_count']} subdomain levels)")

    if features.get("digit_ratio", 0.0) > 0.20:
        reasons.append(f"High numeric character concentration ({int(features['digit_ratio'] * 100)}% digits)")

    if features.get("num_hyphens", 0) > 3:
        reasons.append(f"Excessive hyphenation ({features['num_hyphens']} hyphens), common in brand spoofing")

    if features.get("is_high_risk_tld", 0) == 1:
        reasons.append("Top-level domain (TLD) statistically correlated with elevated registration abuse")

    if not reasons:
        if verdict == "Safe":
            reasons.append("Standard URL structure with clean security parameters.")
        else:
            reasons.append("Structural anomalies detected by machine-learning behavioral profile.")

    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "prob_malicious": round(prob_malicious, 4),
        "prob_safe": round(prob_safe, 4),
        "domain_reputation": domain_reputation,
        "features": features,
        "reasons": reasons,
        "model_used": os.path.basename(MODEL_PATH)
    }


def main_cli():
    sample_urls = [
        "https://google.com",
        "https://docs.python.org/3/library/math.html",
        "https://react.dev/learn",
        "https://subdomain.university.edu/courses/cs101/syllabus",
        "http://info.cern.ch/hypertext/WWW/TheProject.html",
        "http://[2001:db8::1]:8080/login/update",
        "http://192.168.1.50:8080/login/paypal/update",
        "http://paypal-security-alert.com//verify-account?token=89234823",
        "https://g5.lu/vu39k",
        "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
        "https://dl.zerotheme.ir/kokorila/cgl-bin/bin.exe",
        "javascript:alert(1)",
    ]

    print("=" * 72)
    print(f"CYBERGUARDIAN URL CLASSIFIER ({os.path.basename(MODEL_PATH)})")
    print("=" * 72)

    for url in sample_urls:
        res = classify(url)
        badge = f"[{res['verdict'].upper():^11}]"
        print(f"\n{badge} -> {url}")
        print(f"    Confidence : {res['confidence'] * 100:.2f}% (P(Malicious)={res['prob_malicious']:.2f})")
        print(f"    Reputation : {res.get('domain_reputation', 'None')}")
        print("    Reasons    :")
        for r in res["reasons"]:
            print(f"      * {r}")


if __name__ == "__main__":
    main_cli()