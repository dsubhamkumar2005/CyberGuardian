from __future__ import annotations

import customtkinter as ctk

from core.pipeline import GuardianPipeline
from ui.theme import PALETTE
from ui.widgets import Card, MetricTile


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, on_goto_scan, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline = pipeline
        self.on_goto_scan = on_goto_scan
        self.grid_columnconfigure((0, 1, 2, 3), weight=1)

        hero = Card(self)
        hero.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 14))
        ctk.CTkLabel(
            hero,
            text="Local phishing desk",
            text_color=PALETTE["accent"],
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=22, pady=(18, 0))
        ctk.CTkLabel(
            hero,
            text="Paste a URL, scan a QR, or watch the clipboard — verdicts stay on this machine.",
            text_color=PALETTE["text"],
            font=ctk.CTkFont(size=20, weight="bold"),
            wraplength=860,
            justify="left",
        ).pack(anchor="w", padx=22, pady=(6, 0))
        ctk.CTkLabel(
            hero,
            text="Pipeline: input → features → classifier → explainable reasons → alert",
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=22, pady=(4, 18))

        self.tiles = [
            MetricTile(self, "Total scans", "0", "Stored in local SQLite"),
            MetricTile(self, "Malicious", "0", "Blocked / warned", accent=PALETTE["malicious"]),
            MetricTile(self, "Suspicious", "0", "Needs a second look", accent=PALETTE["suspicious"]),
            MetricTile(self, "Safe", "0", "No dominant risk signals", accent=PALETTE["safe"]),
        ]
        for i, tile in enumerate(self.tiles):
            tile.grid(row=1, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0 if i == 3 else 8))

        self.clip_card = Card(self)
        self.clip_card.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=14, padx=(0, 8))
        ctk.CTkLabel(
            self.clip_card,
            text="Passive clipboard guard",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(
            self.clip_card,
            text="When enabled, copied links are scanned automatically. The clipboard never leaves this PC.",
            text_color=PALETTE["muted"],
            wraplength=420,
            justify="left",
        ).pack(anchor="w", padx=18)
        self.clip_status = ctk.CTkLabel(
            self.clip_card,
            text="Clipboard monitor: off",
            text_color=PALETTE["cyan"],
        )
        self.clip_status.pack(anchor="w", padx=18, pady=(10, 16))

        actions = Card(self)
        actions.grid(row=2, column=2, columnspan=2, sticky="nsew", pady=14, padx=(8, 0))
        ctk.CTkLabel(actions, text="Quick actions", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 8)
        )
        ctk.CTkButton(
            actions,
            text="Scan a URL or QR",
            fg_color=PALETTE["accent"],
            text_color="#071014",
            hover_color="#25c48d",
            command=self.on_goto_scan,
            height=40,
        ).pack(fill="x", padx=18, pady=(0, 8))
        ctk.CTkLabel(
            actions,
            text="Demo video is recorded separately — this window is the live prototype.",
            text_color=PALETTE["muted"],
            wraplength=360,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 16))

        self.feed = Card(self)
        self.feed.grid(row=3, column=0, columnspan=4, sticky="nsew")
        self.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(self.feed, text="Latest verdicts", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 8)
        )
        self.feed_box = ctk.CTkTextbox(
            self.feed, fg_color=PALETTE["card_alt"], text_color=PALETTE["text"], height=180
        )
        self.feed_box.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    def refresh(self, clipboard_on: bool) -> None:
        snap = self.pipeline.store.analytics()
        self.tiles[0].set(str(snap.total_scans), "Stored in local SQLite")
        self.tiles[1].set(str(snap.malicious), "Blocked / warned")
        self.tiles[2].set(str(snap.suspicious), "Needs a second look")
        self.tiles[3].set(str(snap.safe), "No dominant risk signals")
        self.clip_status.configure(
            text="Clipboard monitor: watching for URLs" if clipboard_on else "Clipboard monitor: off"
        )
        self.feed_box.delete("1.0", "end")
        if not snap.recent:
            self.feed_box.insert("end", "No scans yet. Paste a URL on the Scan page to generate a verdict.\n")
            return
        for row in snap.recent:
            line = f"{row['created_at'][:19]}   {row['verdict'].upper():<12}  {row['source']:<10}  {row['url']}\n"
            self.feed_box.insert("end", line)
