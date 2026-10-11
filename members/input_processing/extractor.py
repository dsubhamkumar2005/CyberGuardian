"""Member 3 — Input Processing & Security (support from Members 2 and 5).

Responsibilities this module should own in the real codebase:
- Normalize pasted URLs
- Decode QR images / camera frames to a payload
- Detect URLs inside clipboard text
- Engineer lexical features for Member 2
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlparse

from core.contracts import ExtractedInput, FeatureSet, ScanRequest

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".zip", ".mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
LOGIN_WORDS = ("login", "signin", "verify", "account", "update", "secure", "password", "bank")
URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)


def looks_like_url(text: str) -> bool:
    text = (text or "").strip()
    if not text or len(text) > 2048:
        return False
    return bool(URL_RE.search(text)) or ("." in text and " " not in text and len(text) > 4)


class InputProcessor:
    def extract(self, request: ScanRequest) -> ExtractedInput:
        raw = (request.raw_input or "").strip()
        notes: list[str] = []
        qr_payload = None

        if request.source == "qr":
            decoded = self.decode_qr(request.image_path, raw)
            qr_payload = decoded
            raw = decoded or raw
            notes.append("QR payload decoded locally on-device.")

        url = self._normalize_url(raw)
        if not url:
            url = raw
            notes.append("Could not normalize to an absolute URL; scanned raw text.")
        return ExtractedInput(url=url, source=request.source, qr_payload=qr_payload, notes=notes)

    def decode_qr(self, image_path: str | None, fallback_text: str) -> str:
        """Try OpenCV/pyzbar if Member 3 installed them; otherwise use pasted text."""
        if image_path:
            try:
                import cv2
                from pyzbar.pyzbar import decode

                img = cv2.imread(image_path)
                if img is not None:
                    found = decode(img)
                    if found:
                        return found[0].data.decode("utf-8", errors="replace")
            except Exception:
                pass
        return fallback_text.strip()

    def extract_url_from_clipboard(self, text: str) -> str | None:
        if not text:
            return None
        match = URL_RE.search(text)
        if match:
            return match.group(0)
        if looks_like_url(text):
            return text.strip()
        return None

    def engineer_features(self, extracted: ExtractedInput) -> FeatureSet:
        url = extracted.url
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc.lower()
        path = (parsed.path or "") + (parsed.query or "")
        reasons: list[str] = list(extracted.notes)

        has_ip = 1.0 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host) else 0.0
        has_at = 1.0 if "@" in url else 0.0
        has_https = 1.0 if parsed.scheme == "https" else 0.0
        tld = ""
        if "." in host:
            tld = "." + host.rsplit(".", 1)[-1]
        suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        has_shortener = 1.0 if any(s in host for s in SHORTENERS) else 0.0
        has_login = 1.0 if any(w in url.lower() for w in LOGIN_WORDS) else 0.0
        dots = host.count(".")
        hyphens = host.count("-")
        subdomains = max(0, dots - 1)
        entropy = _shannon(url)

        if has_ip:
            reasons.append("Hostname is a raw IP address, common in phishing kits.")
        if has_at:
            reasons.append("URL contains '@', which can hide the real destination.")
        if not has_https:
            reasons.append("No HTTPS scheme; credentials would be sent in the clear.")
        if suspicious_tld:
            reasons.append(f"TLD '{tld}' is frequently abused in throwaway phishing domains.")
        if has_shortener:
            reasons.append("Link shortener hides the true landing page.")
        if has_login:
            reasons.append("Path/host uses credential-harvest wording (login/verify/account).")
        if len(url) > 75:
            reasons.append("Unusually long URL, often used to bury the real domain.")
        if subdomains >= 3:
            reasons.append("Deep subdomain chain can impersonate a trusted brand.")

        values = {
            "has_ip": has_ip,
            "url_length": float(len(url)),
            "num_dots": float(dots),
            "num_hyphens": float(hyphens),
            "has_at": has_at,
            "has_https": has_https,
            "suspicious_tld": suspicious_tld,
            "num_subdomains": float(subdomains),
            "has_login_keyword": has_login,
            "has_shortener": has_shortener,
            "entropy": entropy,
        }
        return FeatureSet(values=values, human_reasons=reasons)

    def _normalize_url(self, text: str) -> str:
        text = text.strip()
        if not text:
            return ""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
            if looks_like_url(text):
                text = "http://" + text
            else:
                return ""
        return text


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 3)
