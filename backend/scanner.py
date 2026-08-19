from urllib.parse import urlparse


def scan_url(url):
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
        return {
            "status": "error",
            "message": "Invalid URL"
        }

    # Temporary mock result
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
        "prediction": verdict,
        "confidence": round(max(safe_probability, phishing_probability) * 100, 2),
        "phishing_probability": round(phishing_probability * 100, 2),
        "safe_probability": round(safe_probability * 100, 2),
        "risk_score": risk_score,
        "reasons": [
            "Temporary mock analysis",
            "AI model will be integrated later"
        ]
    }