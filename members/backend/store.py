"""Member 4 — Backend & Security Analytics (support from Member 1).

Local SQLite only. Nothing is synced to the cloud.
Replace/extend this file with richer analytics; keep the method names the UI calls.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import DB_PATH
from core.contracts import AnalyticsSnapshot, ScanResult


class LocalStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    model_name TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    features_json TEXT NOT NULL
                )
                """
            )

    def save_scan(self, result: ScanResult) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    created_at, source, url, verdict, confidence, model_name, reasons, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.created_at.isoformat(),
                    result.request.source,
                    result.extracted.url,
                    result.verdict.value,
                    result.confidence,
                    result.model_name,
                    json.dumps(result.reasons),
                    json.dumps(result.features.values),
                ),
            )

    def recent_scans(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def analytics(self) -> AnalyticsSnapshot:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            counts = {
                row["verdict"]: row["n"]
                for row in conn.execute(
                    "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict"
                )
            }
            sources = {
                row["source"]: row["n"]
                for row in conn.execute(
                    "SELECT source, COUNT(*) AS n FROM scans GROUP BY source"
                )
            }
        recent = self.recent_scans(8)
        return AnalyticsSnapshot(
            total_scans=total,
            malicious=counts.get("malicious", 0),
            suspicious=counts.get("suspicious", 0),
            safe=counts.get("safe", 0),
            by_source=sources,
            recent=recent,
        )

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()
