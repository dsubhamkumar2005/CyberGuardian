from urllib.parse import urlparse
import ipaddress
import math
import pandas as pd
import joblib


def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    Higher entropy generally means the characters
    are more random/complex.
    """
    if not text:
        return 0.0

    frequencies = {}

    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    length = len(text)

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    """
    Check whether the hostname is an IP address.
    Returns:
        1 → IP address
        0 → normal domain
    """
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname):
    """
    Count the number of subdomains.
    """
    if not hostname:
        return 0

    hostname = hostname.rstrip(".")
    parts = hostname.split(".")

    if is_ip_address(hostname):
        return 0

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def count_special_characters(url):
    """
    Count special characters commonly found in URLs.
    """
    special_characters = "@?=-_&%#:/.!"

    count = 0

    for char in url:
        if char in special_characters:
            count += 1

    return count


def extract_features(url):
    """
    Convert a raw URL into numerical features
    that can be given to the ML model.
    """

    url = str(url).strip()

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname

    length = len(url)

    subdomain_count = count_subdomains(hostname)

    uses_ip = is_ip_address(hostname)

    has_https = 1 if parsed_url.scheme.lower() == "https" else 0

    special_char_count = count_special_characters(url)

    shannon_entropy = calculate_entropy(url)

    features = {
        "length": length,
        "subdomain_count": subdomain_count,
        "uses_ip": uses_ip,
        "has_https": has_https,
        "special_char_count": special_char_count,
        "shannon_entropy": shannon_entropy
    }

    return features


# Load trained model
model = joblib.load("models/random_forest_model.pkl")


def classify(url: str) -> dict:

    # 1. Extract features
    features = extract_features(url)

    # 2. Convert features into DataFrame
    X = pd.DataFrame([features])

    # Make sure columns are in the exact same order
    # used during model training
    X = X[
        [
            "length",
            "subdomain_count",
            "uses_ip",
            "has_https",
            "special_char_count",
            "shannon_entropy"
        ]
    ]

    # 3. Make prediction
    prediction = model.predict(X)[0]

    # 4. Get probability
    probabilities = model.predict_proba(X)[0]

    confidence = probabilities[prediction]
    safe_probability = probabilities[0]
    phishing_probability = probabilities[1]
    # 5. Generate explanations
    reasons = []

    if features["uses_ip"]:
        reasons.append("Uses IP address instead of domain")

    if not features["has_https"]:
        reasons.append("No HTTPS encryption")

    if features["special_char_count"] > 6:
        reasons.append("High number of special characters")

    if features["shannon_entropy"] > 4.0:
        reasons.append("High URL randomness")

    if features["length"] > 75:
        reasons.append("Unusually long URL")

    if features["subdomain_count"] > 2:
        reasons.append("Multiple subdomains")

    # 6. Convert prediction to human-readable verdict
    if prediction == 1:
        verdict = "Malicious"
    else:
        verdict = "Safe"

    # 7. If nothing suspicious was found
    if not reasons:
        reasons.append("No suspicious characteristics detected.")

    # 8. Return result
    return {
    "verdict": verdict,
    "confidence": round(float(confidence), 4),
    "safe_probability": round(float(safe_probability), 4),
    "phishing_probability": round(float(phishing_probability), 4),
    "features": features,
    "reasons": reasons
    }

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://login.example.com/account/update",
        "http://192.168.1.50/login/paypal/update",
        "http://www.deskthipk.com/"
    ]

    print("=" * 60)
    print("URL CLASSIFIER TEST")
    print("=" * 60)

    for url in test_urls:

        result = classify(url)

        print("\nURL:")
        print(url)

        print("\nVerdict:", result["verdict"])
        print("Confidence:", result["confidence"])

        print("\nFeatures:")

        for feature, value in result["features"].items():
            print(f"  {feature}: {value}")

        print("\nReasons:")

        for reason in result["reasons"]:
            print("  -", reason)

        print("-" * 60)