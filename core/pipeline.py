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
        features = self.input_proc.engineer_features(extracted)
        verdict, confidence, model_name, reasons = self.ml.predict(features)
        result = ScanResult(
            request=request,
            extracted=extracted,
            features=features,
            verdict=verdict,
            confidence=confidence,
            model_name=model_name,
            reasons=reasons,
        )
        self.store.save_scan(result)
        return result

    def password_k_anonymity_prefix(self, password: str) -> tuple[str, str]:
        """HIBP-style k-anonymity: only the first 5 SHA-1 hex chars would ever leave the machine.

        The UI never sends the password. Member 3/4 can call the range API later.
        """
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return digest[:5], digest[5:]
