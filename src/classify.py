import pandas as pd
import joblib

from feature_extractor import extract_features


# Load the trained Random Forest model
model = joblib.load("models/url_classifier.pkl")


def classify(url: str) -> dict:

    # Extract the same six features used during model training
    features = extract_features(url)

    # Convert the feature dictionary into a DataFrame
    X = pd.DataFrame([features])

    # Make prediction
    prediction = model.predict(X)[0]

    # Get probability for both classes
    probabilities = model.predict_proba(X)[0]

    # Confidence is the probability of the predicted class
    confidence = probabilities[prediction]

    # Generate human-readable reasons
    reasons = []

    if features["uses_ip"] == 1:
        reasons.append("Uses IP address instead of domain")

    if features["has_https"] == 0:
        reasons.append("No HTTPS encryption")

    if features["special_char_count"] > 5:
        reasons.append("High number of special characters")

    if features["length"] > 75:
        reasons.append("Unusually long URL")

    if features["shannon_entropy"] > 4.0:
        reasons.append("High URL randomness")

    if features["subdomain_count"] > 2:
        reasons.append("Large number of subdomains")

    # Convert numerical prediction into readable verdict
    if prediction == 1:
        verdict = "Malicious"
    else:
        verdict = "Safe"

    return {
        "verdict": verdict,
        "confidence": round(float(confidence), 2),
        "features": features,
        "reasons": reasons
    }


# --------------------------------------------------
# TESTING
# --------------------------------------------------

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

        print("\nURL:")
        print(url)

        result = classify(url)

        print("\nVerdict:", result["verdict"])
        print("Confidence:", result["confidence"])

        print("\nFeatures:")

        for feature, value in result["features"].items():
            print(f"  {feature}: {value}")

        print("\nReasons:")

        if result["reasons"]:
            for reason in result["reasons"]:
                print("  -", reason)
        else:
            print("  No suspicious characteristics detected.")

        print("-" * 60)