from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CyberGuardian Backend")


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "status": "success",
        "message": "CyberGuardian backend is running!"
    }


@app.post("/scan")
def scan_url(request: URLRequest):

    url = request.url

    # Temporary mock AI result
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