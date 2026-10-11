import os
from urllib.parse import urlparse
import pandas as pd
import joblib
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "url_classifier.pkl")

# Fallback to random_forest_model.pkl if url_classifier.pkl is not found
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest_model.pkl")

model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    "length",
    "path_length",
    "query_length",
    "subdomain_count",
    "num_subdirectories",
    "uses_ip",
    "has_https",
    "special_char_count",
    "shannon_entropy",
    "num_digits",
    "digit_ratio",
    "num_hyphens",
    "has_at_symbol",
    "has_double_slash_redirect",
    "is_shortened",
    "has_suspicious_keywords"
]

TRUSTED_DOMAINS = {
    "wikipedia.org", "wikimedia.org", "google.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "youtube.com",
    "mozilla.org", "python.org", "stackoverflow.com", "nytimes.com",
    "bbc.com", "reuters.com", "cloudflare.com", "nih.gov", "cisa.gov",
    "w3.org", "ietf.org", "owasp.org", "kubernetes.io", "docker.com",
    "pypi.org", "arxiv.org", "stanford.edu", "mit.edu", "harvard.edu"
}


def is_trusted_domain(hostname: str) -> bool:
    if not hostname:
        return False
    h = hostname.lower().strip()
    return any(h == d or h.endswith("." + d) for d in TRUSTED_DOMAINS)


def classify(url: str) -> dict:
    global model
    if model is None:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please run train.py first.")

    features = extract_features(url)

    parsed_input = url if "://" in url else "http://" + url
    hostname = (urlparse(parsed_input).hostname or "").lower()
    trusted = is_trusted_domain(hostname)

    if (trusted and features["has_https"] == 1 
            and features["uses_ip"] == 0 
            and features["has_at_symbol"] == 0 
            and features["has_double_slash_redirect"] == 0):
        return {
            "verdict": "Safe",
            "confidence": 1.0,
            "features": features,
            "reasons": ["Verified high-reputation domain with valid HTTPS encryption."]
        }

    X = pd.DataFrame([features])[FEATURE_COLUMNS]

    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    confidence = float(probabilities[prediction])

    reasons = []

    if features["uses_ip"] == 1:
        reasons.append("Uses direct IP address instead of domain name")

    if features["has_https"] == 0:
        reasons.append("No HTTPS encryption (insecure HTTP protocol)")

    if features["is_shortened"] == 1:
        reasons.append("Uses URL shortener to conceal destination")

    if features["has_suspicious_keywords"] == 1:
        reasons.append("Contains credential/phishing keywords (e.g. login, verify, secure)")

    if features["has_at_symbol"] == 1:
        reasons.append("Contains '@' symbol (credential spoofing / open redirect technique)")

    if features["has_double_slash_redirect"] == 1:
        reasons.append("Contains '//' in URL path (open redirect attempt)")

    if features["shannon_entropy"] > 4.2:
        reasons.append(f"High character randomness / entropy ({features['shannon_entropy']})")

    if features["length"] > 85:
        reasons.append(f"Unusually long URL ({features['length']} characters)")

    if features["num_hyphens"] > 2:
        reasons.append(f"Multiple hyphens ({features['num_hyphens']}), common in brand impersonation")

    if features["subdomain_count"] > 2:
        reasons.append(f"Chained subdomains ({features['subdomain_count']} subdomains)")

    if features["digit_ratio"] > 0.20:
        reasons.append(f"High digit ratio ({int(features['digit_ratio'] * 100)}% of URL is numbers)")

    if features["special_char_count"] > 9:
        reasons.append(f"High special character count ({features['special_char_count']})")

    if features["path_length"] > 70:
        reasons.append("Unusually deep or complex path structure")

    verdict = "Malicious" if prediction == 1 else "Safe"

    if not reasons:
        reasons.append("No suspicious characteristics detected.")

    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "features": features,
        "reasons": reasons
    }


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://en.wikipedia.org/wiki/Cybersecurity",
        "https://login.example.com/account/update",
        "http://192.168.1.50/login/paypal/update",
        "http://www.deskthipk.com/",
        "https://g5.lu/vu39k",
        "http://paypal-security-alert.com//verify-account?token=89234823"
    ]

    print("=" * 60)
    print("URL CLASSIFIER TEST (16 PARAMETERS)")
    print("=" * 60)

    for test_url in test_urls:
        res = classify(test_url)
        print(f"\nURL: {test_url}")
        print(f"Verdict   : {res['verdict']}")
        print(f"Confidence: {res['confidence'] * 100:.2f}%")
        print("Reasons:")
        for r in res["reasons"]:
            print(f"  - {r}")
        print("-" * 60)