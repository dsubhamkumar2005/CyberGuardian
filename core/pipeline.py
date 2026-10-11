"""UI-facing orchestration. Member 1 owns this glue; teammates own the callees."""

from __future__ import annotations

import hashlib

from core.contracts import ScanRequest, ScanResult
from core.adapters import HardwareBridge, InputProcessor, LocalStore, MLClassifier


class GuardianPipeline:
    def __init__(self) -> None:
        self.input_proc = InputProcessor()
        self.ml = MLClassifier()
        self.store = LocalStore()
        self.hardware = HardwareBridge()

    
    def scan(self, request: ScanRequest) -> ScanResult:
        extracted = self.input_proc.extract(request)

        verdict, confidence, model_name, reasons, features, model_output = (
            self.ml.predict(extracted.url)
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
                "prob_malicious": model_output.get("prob_malicious", 0.0),
                "prob_safe": model_output.get("prob_safe", 0.0),
                "decision_threshold": model_output.get("decision_threshold", 0.5),
                "domain_reputation": model_output.get("domain_reputation", "None"),
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
