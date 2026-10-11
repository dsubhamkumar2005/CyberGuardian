from __future__ import annotations

import customtkinter as ctk

from core.pipeline import GuardianPipeline
from ui.theme import PALETTE
from ui.widgets import Card


PRIVACY_POINTS = [
    "No scan data leaves this machine. There is no cloud account and no telemetry.",
    "History lives in a local SQLite file under data/cyberguardian.sqlite.",
    "Clipboard monitoring is opt-in and processed in-process only.",
    "Passwords are never stored. Optional HIBP-style checks send only a 5-character SHA-1 prefix (k-anonymity), never the password.",
    "QR images are decoded on-device. The photo is not uploaded.",
]


class PrivacyPage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline = pipeline
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="Security, privacy & compliance", font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))

        card = Card(self)
        card.grid(row=1, column=0, sticky="ew")
        for i, point in enumerate(PRIVACY_POINTS):
            ctk.CTkLabel(
                card,
                text=f"{i + 1}.  {point}",
                wraplength=820,
                justify="left",
                text_color=PALETTE["text"],
            ).pack(anchor="w", padx=20, pady=(16 if i == 0 else 8, 8 if i < 4 else 18))

        pw = Card(self)
        pw.grid(row=2, column=0, sticky="ew", pady=14)
        ctk.CTkLabel(pw, text="Password prefix (k-anonymity helper)", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 4)
        )
        ctk.CTkLabel(
            pw,
            text="Type a password to see the SHA-1 prefix that would be queried. The full hash and password stay here.",
            text_color=PALETTE["muted"],
            wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=18)
        row = ctk.CTkFrame(pw, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=12)
        self.pw_entry = ctk.CTkEntry(row, show="•", placeholder_text="Password (never saved)")
        self.pw_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(row, text="Show prefix only", command=self._prefix).pack(side="left")
        self.pw_out = ctk.CTkLabel(pw, text="", text_color=PALETTE["cyan"])
        self.pw_out.pack(anchor="w", padx=18, pady=(0, 16))

        self.hibp = ctk.CTkSwitch(
            self,
            text="Allow HIBP range API later (prefix only). Default OFF — fully offline.",
        )
        self.hibp.grid(row=3, column=0, sticky="w", pady=(4, 0))

    def _prefix(self) -> None:
        secret = self.pw_entry.get()
        if not secret:
            self.pw_out.configure(text="Nothing entered.")
            return
        prefix, suffix = self.pipeline.password_k_anonymity_prefix(secret)
        self.pw_out.configure(
            text=f"Would transmit only prefix {prefix}  •  local suffix kept here ({suffix[:6]}…)"
        )
        self.pw_entry.delete(0, "end")
