"""Shared types used by UI and every teammate module.

Member 2 (ML), Member 3 (input), Member 4 (backend), and Member 5 (hardware)
should import these instead of inventing their own dict shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class VerdictLabel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


ScanSource = Literal["url", "qr", "clipboard", "hardware", "password"]


@dataclass
class ScanRequest:
    source: ScanSource
    raw_input: str
    image_path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedInput:
    """Output of Member 3 — Input Processing."""

    url: str
    source: ScanSource
    qr_payload: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class FeatureSet:
    """Output of Member 3 / consumed by Member 2."""

    values: dict[str, float]
    human_reasons: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Final payload the UI renders."""

    request: ScanRequest
    extracted: ExtractedInput
    features: FeatureSet
    verdict: VerdictLabel
    confidence: float
    model_name: str
    reasons: list[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at.isoformat(),
            "source": self.request.source,
            "url": self.extracted.url,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "model_name": self.model_name,
            "reasons": " | ".join(self.reasons),
        }


@dataclass
class AnalyticsSnapshot:
    total_scans: int = 0
    malicious: int = 0
    suspicious: int = 0
    safe: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    recent: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class HardwareStatus:
    connected: bool = False
    port: str = ""
    last_payload: str = ""
    message: str = "No device connected"
