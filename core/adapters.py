"""Read-only bridges between the Member 1 UI and the supplied member ZIPs.

The archives in ``D:/IDP/members`` remain the source of truth: this module only
reads them.  The app is still usable when optional ML dependencies are absent.
"""

from __future__ import annotations

import ipaddress
import math
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from config import DB_PATH, ROOT
from core.contracts import AnalyticsSnapshot, ExtractedInput, FeatureSet, HardwareStatus, ScanRequest, ScanResult, VerdictLabel


MEMBERS_DIR = ROOT.parent / "members"
ML_ARCHIVE = MEMBERS_DIR / "CyberGuardian-josh-ml.zip"


class InputProcessor:
    """Normalises input and mirrors the six features used by the ML member."""

    def extract(self, request: ScanRequest) -> ExtractedInput:
        raw = request.raw_input.strip()
        if request.image_path and not raw:
            raw = self._decode_image(request.image_path)
        url = self._normalise_url(raw)
        return ExtractedInput(url=url, source=request.source, qr_payload=raw if request.source == "qr" else None)

    def extract_url_from_clipboard(self, text: str) -> str | None:
        for token in text.replace("\n", " ").split():
            candidate = self._normalise_url(token)
            if urlparse(candidate).netloc:
                return candidate
        return None

    def engineer_features(self, extracted: ExtractedInput) -> FeatureSet:
        url = extracted.url
        parsed = urlparse(url)
        host = parsed.hostname or ""
        try:
            uses_ip = int(bool(ipaddress.ip_address(host)))
        except ValueError:
            uses_ip = 0
        parts = host.rstrip(".").split(".") if host else []
        subdomains = 0 if uses_ip else max(len(parts) - 2, 0)
        entropy = self._entropy(url)
        values = {
            "length": float(len(url)), "subdomain_count": float(subdomains),
            "uses_ip": float(uses_ip), "has_https": float(parsed.scheme.lower() == "https"),
            "special_char_count": float(sum(c in "@?=-_&%#:/!." for c in url)),
            "shannon_entropy": round(entropy, 4),
        }
        return FeatureSet(values=values)

    @staticmethod
    def _normalise_url(value: str) -> str:
        value = value.strip().strip("<>'\"")

        if not value:
            return ""

        # Reject explicit non-web schemes.
        parsed = urlparse(value)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return value

        # Add HTTPS only to inputs that look like a hostname or IP address.
        if "://" not in value:
            candidate = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if not candidate or "." not in candidate:
                return value
            value = "https://" + value

        # Validate the resulting web URL.
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return value

        return value

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        return -sum((value.count(c) / len(value)) * math.log2(value.count(c) / len(value)) for c in set(value))

    @staticmethod
    def _decode_image(path: str) -> str:
        try:
            import cv2  # optional dependency from Member 3
            detector = cv2.QRCodeDetector()
            decoded, _, _ = detector.detectAndDecode(cv2.imread(path))
            return decoded.strip()
        except Exception:
            return ""



class MLClassifier:
    """Adapter for the production 23-feature URL classifier."""

    def predict(
        self, url: str
    ) -> tuple[VerdictLabel, float, str, list[str], FeatureSet, dict]:
        from src.classifier import classify

        result = classify(url)

        verdict_text = result["verdict"]
        if verdict_text == "Safe":
            label = VerdictLabel.SAFE
        elif verdict_text == "Malicious":
            label = VerdictLabel.MALICIOUS
        else:
            label = VerdictLabel.UNKNOWN

        features = FeatureSet(
            values={
                key: float(value)
                for key, value in result.get("features", {}).items()
                if isinstance(value, (int, float, bool))
            },
            human_reasons=list(result.get("reasons", [])),
        )

        return (
            label,
            float(result["confidence"]),
            "Production Random Forest v3",
            list(result.get("reasons", [])),
            features,
            result,
        )



class LocalStore:
    def __init__(self) -> None:
        DB_PATH.parent.mkdir(exist_ok=True)
        with sqlite3.connect(DB_PATH) as con:
            con.execute("CREATE TABLE IF NOT EXISTS ui_scans (created_at TEXT, source TEXT, url TEXT, verdict TEXT, confidence REAL, model_name TEXT, reasons TEXT)")

    def save_scan(self, result: ScanResult) -> None:
        row = result.to_row()
        with sqlite3.connect(DB_PATH) as con:
            con.execute("INSERT INTO ui_scans VALUES (:created_at,:source,:url,:verdict,:confidence,:model_name,:reasons)", row)

    def recent_scans(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(DB_PATH) as con:
            con.row_factory = sqlite3.Row
            return [dict(row) for row in con.execute("SELECT * FROM ui_scans ORDER BY created_at DESC LIMIT ?", (limit,))]

    def analytics(self) -> AnalyticsSnapshot:
        rows = self.recent_scans(5000)
        by_source: dict[str, int] = {}
        for row in rows: by_source[row["source"]] = by_source.get(row["source"], 0) + 1
        return AnalyticsSnapshot(total_scans=len(rows), safe=sum(r["verdict"] == "safe" for r in rows), suspicious=sum(r["verdict"] == "suspicious" for r in rows), malicious=sum(r["verdict"] == "malicious" for r in rows), by_source=by_source, recent=rows[:8])


class HardwareBridge:
    def __init__(self) -> None: self.port = "COM3"; self.connected = False; self.last_payload = ""
    def connect(self) -> HardwareStatus:
        self.connected = True; return HardwareStatus(True, self.port, self.last_payload, f"Demo bridge connected on {self.port}")
    def disconnect(self) -> HardwareStatus:
        self.connected = False; return HardwareStatus(False, self.port, self.last_payload, "Disconnected")
    def inject_demo_payload(self, payload: str) -> None: self.last_payload = payload
