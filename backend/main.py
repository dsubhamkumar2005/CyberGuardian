from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from backend.scanner import scan_url

app = FastAPI(title="CyberGuardian Backend")

# Serve the new CyberGuardian web dashboard
app.mount("/web", StaticFiles(directory="web", html=True), name="web")


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