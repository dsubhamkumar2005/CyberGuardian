from urllib.parse import urlparse
import re
import ipaddress

from src.classifier import classify
scanned_urls = set()

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


def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_extra_features(url):
    parsed_url = urlparse(url)

    domain = parsed_url.hostname or ""

    domain_parts = domain.split(".")
    num_subdomains = max(len(domain_parts) - 2, 0)

    url_lower = url.lower()

    has_suspicious_keyword = any(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    num_special_characters = len(
        re.findall(r"[^a-zA-Z0-9]", url)
    )

    return {
        "url": url,
        "domain": domain,
        "url_length": len(url),
        "uses_https": parsed_url.scheme.lower() == "https",
        "has_ip": is_ip_address(domain),
        "num_dots": url.count("."),
        "has_at_symbol": "@" in url,
        "has_suspicious_keyword": has_suspicious_keyword,
        "num_special_characters": num_special_characters,
        "num_subdomains": num_subdomains
    }


def scan_url(url):

    # Validate URL
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
        return {
            "status": "error",
            "message": "Invalid URL"
        }

    # Check duplicate
    duplicate = url in scanned_urls

    # Store URL
    scanned_urls.add(url)

    # Run ML classification
    result = classify(url)

    # Extract additional features
    extra_features = get_extra_features(url)

    # Combine features
    all_features = {
        **extra_features,
        **result["features"]
    }

    return {
        "status": "success",

        "valid": True,
        "duplicate": duplicate,

        "prediction": result["verdict"],
        "confidence": round(result["confidence"] * 100, 2),

        "safe_probability": round(
            result["safe_probability"] * 100, 2
        ),

        "phishing_probability": round(
            result["phishing_probability"] * 100, 2
        ),

        "risk_score": round(
            result["phishing_probability"] * 100
        ),

        "features": all_features,

        "reasons": result["reasons"]
    }
