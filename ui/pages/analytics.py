from __future__ import annotations

import customtkinter as ctk

from core.pipeline import GuardianPipeline
from ui.theme import PALETTE
from ui.widgets import Card, MetricTile


class AnalyticsPage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline = pipeline
        self.grid_columnconfigure((0, 1, 2), weight=1)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(self, text="Security analytics", font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )

        self.m_total = MetricTile(self, "Volume", "0", "All local scans")
        self.m_risk = MetricTile(self, "Risk mix", "—", "Malicious share", accent=PALETTE["malicious"])
        self.m_src = MetricTile(self, "Top source", "—", "How threats arrive", accent=PALETTE["cyan"])
        self.m_total.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        self.m_risk.grid(row=1, column=1, sticky="ew", padx=8)
        self.m_src.grid(row=1, column=2, sticky="ew", padx=(8, 0))

        card = Card(self)
        card.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=14)
        ctk.CTkLabel(
            card,
            text="Member 4 owns this store. Charts below read the same SQLite the UI writes.",
            text_color=PALETTE["muted"],
        ).pack(anchor="w", padx=18, pady=(16, 8))
        self.canvas = ctk.CTkCanvas(
            card, bg=PALETTE["card"], highlightthickness=0, height=260
        )
        self.canvas.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    def refresh(self) -> None:
        snap = self.pipeline.store.analytics()
        self.m_total.set(str(snap.total_scans))
        share = 0 if snap.total_scans == 0 else snap.malicious / snap.total_scans
        self.m_risk.set(f"{share:.0%}", f"{snap.malicious} malicious / {snap.total_scans} total")
        top_src = max(snap.by_source, key=snap.by_source.get) if snap.by_source else "—"
        self.m_src.set(top_src, str(snap.by_source) if snap.by_source else "No source breakdown yet")

        self.canvas.delete("all")
        w = max(self.canvas.winfo_width(), 640)
        h = max(self.canvas.winfo_height(), 240)
        bars = [
            ("Safe", snap.safe, PALETTE["safe"]),
            ("Suspicious", snap.suspicious, PALETTE["suspicious"]),
            ("Malicious", snap.malicious, PALETTE["malicious"]),
        ]
        peak = max((b[1] for b in bars), default=1) or 1
        gap = 40
        bar_w = (w - gap * 4) / 3
        for i, (name, value, color) in enumerate(bars):
            x0 = gap + i * (bar_w + gap)
            bh = (value / peak) * (h - 70)
            y0 = h - 36 - bh
            self.canvas.create_rectangle(x0, y0, x0 + bar_w, h - 36, fill=color, outline="")
            self.canvas.create_text(
                x0 + bar_w / 2, h - 18, text=f"{name} ({value})", fill=PALETTE["text"], font=("Segoe UI", 12)
            )
