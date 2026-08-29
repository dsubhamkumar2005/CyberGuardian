from urllib.parse import urlparse
import math
import re
import ipaddress


# Suspicious words commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "bank",
    "password",
    "signin",
    "confirm",
    "payment",
    "paypal",
]


def shannon_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    length = len(text)
    frequency = {}

    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def is_ip_address(hostname):
    """Check whether the hostname is an IP address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url):
    """Extract URL features for the AI/ML model."""

    parsed_url = urlparse(url)

    domain = parsed_url.hostname or ""

    # Count subdomains
    domain_parts = domain.split(".")
    num_subdomains = max(len(domain_parts) - 2, 0)

    # Check suspicious keywords
    url_lower = url.lower()
    has_suspicious_keyword = any(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # Count special characters
    num_special_characters = len(
        re.findall(r"[^a-zA-Z0-9]", url)
    )

    features = {
        "url": url,
        "domain": domain,
        "url_length": len(url),
        "uses_https": parsed_url.scheme.lower() == "https",
        "has_ip": is_ip_address(domain),
        "num_dots": url.count("."),
        "has_at_symbol": "@" in url,
        "has_suspicious_keyword": has_suspicious_keyword,
        "num_special_characters": num_special_characters,
        "num_subdomains": num_subdomains,
        "shannon_entropy": shannon_entropy(url)
    }

    return features


def scan_url(url):
    """Validate URL and extract features."""

    parsed_url = urlparse(url)

    # Validate URL
    if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
        return {
            "status": "error",
            "message": "Invalid URL"
        }

    # Extract features
    features = extract_features(url)

    # Temporary mock result
    # AI model will be connected later
    prediction = 0
    safe_probability = 0.91
    phishing_probability = 0.09

    if prediction == 0:
        verdict = "Safe"
    else:
        verdict = "Phishing"

    risk_score = round(phishing_probability * 100)

    return {
        "status": "success",

        # Input-processing information
        "valid": True,
        "duplicate": False,
        "features": features,

        # Temporary AI result
        "prediction": verdict,
        "confidence": round(
            max(safe_probability, phishing_probability) * 100,
            2
        ),
        "phishing_probability": round(
            phishing_probability * 100,
            2
        ),
        "safe_probability": round(
            safe_probability * 100,
            2
        ),
        "risk_score": risk_score,

        "reasons": [
            "Temporary mock analysis",
            "AI model will be integrated later"
        ]
    }