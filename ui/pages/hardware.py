from __future__ import annotations

import customtkinter as ctk

from core.contracts import ScanRequest
from core.pipeline import GuardianPipeline
from ui.theme import PALETTE
from ui.widgets import Card


class HardwarePage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, on_scan, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline = pipeline
        self.on_scan = on_scan
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Hardware bridge", font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        card = Card(self)
        card.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(
            card,
            text="ESP32 / RFID is Member 5’s track. The desk already exposes connect, poll, and a demo inject so UI integration is not blocked.",
            wraplength=820,
            justify="left",
            text_color=PALETTE["muted"],
        ).pack(anchor="w", padx=18, pady=(16, 8))
        self.status = ctk.CTkLabel(card, text="Idle", text_color=PALETTE["cyan"])
        self.status.pack(anchor="w", padx=18, pady=(0, 8))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(0, 8))
        self.port = ctk.CTkEntry(row, placeholder_text="COM3 or /dev/ttyUSB0", width=200)
        self.port.insert(0, "COM3")
        self.port.pack(side="left", padx=(0, 8))
        ctk.CTkButton(row, text="Connect", command=self._connect).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Disconnect", fg_color=PALETTE["card_alt"], command=self._disconnect).pack(
            side="left", padx=4
        )

        demo = Card(self)
        demo.grid(row=2, column=0, sticky="ew", pady=14)
        ctk.CTkLabel(demo, text="Firmware not flashed yet?", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 4)
        )
        ctk.CTkLabel(
            demo,
            text="Inject a sample payload as if the ESP32 scanned a QR. The same pipeline as paste/QR runs.",
            text_color=PALETTE["muted"],
            wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=18)
        self.demo_url = ctk.CTkEntry(demo, placeholder_text="https://example-login.xyz/verify")
        self.demo_url.pack(fill="x", padx=18, pady=10)
        ctk.CTkButton(
            demo,
            text="Inject hardware payload",
            fg_color=PALETTE["cyan"],
            text_color="#071014",
            command=self._inject,
        ).pack(anchor="w", padx=18, pady=(0, 16))

        roadmap = Card(self)
        roadmap.grid(row=3, column=0, sticky="ew")
        ctk.CTkLabel(roadmap, text="Roadmap (not claimed as built)", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 6)
        )
        for line in (
            "ESP32 serial JSON: {source, payload} → this page → pipeline.scan",
            "RFID stretch: badge/token presence as a second factor for unlock of the desk",
            "Browser extension and mobile clients are future work, not this prototype",
        ):
            ctk.CTkLabel(roadmap, text="•  " + line, wraplength=800, justify="left").pack(
                anchor="w", padx=18, pady=4
            )
        ctk.CTkLabel(roadmap, text="", height=8).pack()

    def _connect(self) -> None:
        self.pipeline.hardware.port = self.port.get().strip() or "COM3"
        status = self.pipeline.hardware.connect()
        self.status.configure(text=status.message)

    def _disconnect(self) -> None:
        status = self.pipeline.hardware.disconnect()
        self.status.configure(text=status.message)

    def _inject(self) -> None:
        url = self.demo_url.get().strip()
        if not url:
            return
        self.pipeline.hardware.inject_demo_payload(url)
        self.status.configure(text=f"Last payload: {url}")
        result = self.pipeline.scan(ScanRequest(source="hardware", raw_input=url))
        self.on_scan(result)
