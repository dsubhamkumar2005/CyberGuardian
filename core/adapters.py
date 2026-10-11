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
        if value and "://" not in value:
            value = "https://" + value
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
    """Uses the supplied Random Forest if pandas/joblib are installed; otherwise local scoring."""

    def predict(self, features: FeatureSet) -> tuple[VerdictLabel, float, str, list[str]]:
        prediction = self._member_model(features)
        if prediction is not None:
            malicious, confidence = prediction
            label = VerdictLabel.MALICIOUS if malicious else VerdictLabel.SAFE
            return label, confidence, "Member ML Random Forest", self._reasons(features)

        risk = self._risk(features)
        label = VerdictLabel.MALICIOUS if risk >= 0.72 else VerdictLabel.SUSPICIOUS if risk >= 0.42 else VerdictLabel.SAFE
        confidence = max(risk, 1 - risk) if label != VerdictLabel.SUSPICIOUS else 0.58
        return label, round(confidence, 4), "Local compatibility scorer", self._reasons(features)

    @staticmethod
    def _risk(features: FeatureSet) -> float:
        v = features.values
        return min(0.96, 0.06 + .35 * v["uses_ip"] + .18 * (1 - v["has_https"]) + .18 * min(v["subdomain_count"] / 3, 1) + .13 * min(v["special_char_count"] / 10, 1) + .10 * min(v["length"] / 100, 1) + .10 * min(v["shannon_entropy"] / 5, 1))

    @staticmethod
    def _reasons(features: FeatureSet) -> list[str]:
        v = features.values
        reasons = []
        if v["uses_ip"]: reasons.append("Uses an IP address instead of a domain")
        if not v["has_https"]: reasons.append("The link does not use HTTPS")
        if v["subdomain_count"] > 2: reasons.append("Contains multiple subdomains")
        if v["special_char_count"] > 6: reasons.append("Contains an unusually high number of special characters")
        if v["length"] > 75: reasons.append("URL is unusually long")
        if v["shannon_entropy"] > 4: reasons.append("URL has high character randomness")
        return reasons or ["No dominant phishing indicators were found."]

    @staticmethod
    def _member_model(features: FeatureSet) -> tuple[bool, float] | None:
        if not ML_ARCHIVE.exists(): return None
        try:
            import io
            import joblib
            import pandas as pd
            with zipfile.ZipFile(ML_ARCHIVE) as archive:
                raw = archive.read("CyberGuardian-josh-ml/models/random_forest_model.pkl")
            model = joblib.load(io.BytesIO(raw))
            columns = ["length", "subdomain_count", "uses_ip", "has_https", "special_char_count", "shannon_entropy"]
            row = pd.DataFrame([[features.values[c] for c in columns]], columns=columns)
            predicted = int(model.predict(row)[0])
            probability = float(model.predict_proba(row)[0][predicted])
            return bool(predicted), probability
        except Exception:
            return None


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
