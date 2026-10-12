"""UI-facing orchestration. Member 1 owns this glue; teammates own the callees."""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from core.contracts import FeatureSet, ScanRequest, ScanResult, VerdictLabel
from core.adapters import HardwareBridge, InputProcessor, LocalStore, MLClassifier


class GuardianPipeline:
    def __init__(self) -> None:
        self.input_proc = InputProcessor()
        self.ml = MLClassifier()
        self.store = LocalStore()
        self.hardware = HardwareBridge()

    def scan(self, request: ScanRequest) -> ScanResult:
        extracted = self.input_proc.extract(request)
        parsed = urlparse(extracted.url)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or ("." not in hostname and ":" not in hostname)
        ):
            result = ScanResult(
                request=request,
                extracted=extracted,
                features=FeatureSet(values={}),
                verdict=VerdictLabel.UNKNOWN,
                confidence=0.0,
                model_name="URL validation",
                reasons=["Invalid URL format. Enter a valid HTTP or HTTPS domain or IP address."],
                extra={"validation_error": True},
            )
            self.store.save_scan(result)
            return result

        verdict, confidence, model_name, reasons, features, output = self.ml.predict(
            extracted.url
        )
        result = ScanResult(
            request=request,
            extracted=extracted,
            features=features,
            verdict=verdict,
            confidence=confidence,
            model_name=model_name,
            reasons=reasons,
            extra={
                "prob_malicious": output.get("prob_malicious", 0.0),
                "prob_safe": output.get("prob_safe", 0.0),
                "decision_threshold": output.get("decision_threshold", 0.5),
                "domain_reputation": output.get("domain_reputation", "None"),
            },
        )
        self.store.save_scan(result)
        return result

    def password_k_anonymity_prefix(self, password: str) -> tuple[str, str]:
        """HIBP-style k-anonymity: only the first 5 SHA-1 hex chars would ever leave the machine.

        The UI never sends the password. Member 3/4 can call the range API later.
        """
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return digest[:5], digest[5:]
