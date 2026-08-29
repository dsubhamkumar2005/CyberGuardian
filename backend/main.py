from fastapi import FastAPI
from pydantic import BaseModel
from backend.scanner import scan_url

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
def scan(request: URLRequest):
    return scan_url(request.url)