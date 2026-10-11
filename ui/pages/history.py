from __future__ import annotations

import customtkinter as ctk

from core.pipeline import GuardianPipeline
from ui.theme import PALETTE, verdict_color
from ui.widgets import Card


class HistoryPage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline = pipeline
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(self, text="Scan history", font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )
        card = Card(self)
        card.grid(row=1, column=0, sticky="nsew")
        self.box = ctk.CTkTextbox(card, fg_color=PALETTE["card_alt"])
        self.box.pack(fill="both", expand=True, padx=12, pady=12)

    def refresh(self) -> None:
        rows = self.pipeline.store.recent_scans(200)
        self.box.delete("1.0", "end")
        if not rows:
            self.box.insert("end", "History is empty. Local SQLite file: data/cyberguardian.sqlite\n")
            return
        header = f"{'WHEN':<22} {'VERDICT':<12} {'SRC':<10} URL\n"
        self.box.insert("end", header)
        self.box.insert("end", "-" * 88 + "\n")
        for row in rows:
            self.box.insert(
                "end",
                f"{row['created_at'][:19]:<22} {row['verdict']:<12} {row['source']:<10} {row['url']}\n",
            )
        # Color is limited in textbox; verdict column is still scannable for demos.
        _ = verdict_color
