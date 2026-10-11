from __future__ import annotations

import customtkinter as ctk

from config import APP_NAME, APP_VERSION, COLLEGE_NAME, DOMAIN, TEAM, TEAM_NAME
from ui.theme import PALETTE
from ui.widgets import Card


class AboutPage(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure((0, 1), weight=1)

        hero = Card(self)
        hero.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ctk.CTkLabel(hero, text=APP_NAME, font=ctk.CTkFont(size=28, weight="bold")).pack(
            anchor="w", padx=22, pady=(18, 0)
        )
        ctk.CTkLabel(
            hero,
            text=f"{TEAM_NAME}  ·  {DOMAIN}  ·  {COLLEGE_NAME}  ·  v{APP_VERSION}",
            text_color=PALETTE["muted"],
        ).pack(anchor="w", padx=22, pady=(4, 18))

        for i, member in enumerate(TEAM):
            card = Card(self)
            r, c = divmod(i, 2)
            card.grid(row=r + 1, column=c, sticky="nsew", padx=(0 if c == 0 else 8, 8 if c == 0 else 0), pady=8)
            ctk.CTkLabel(
                card,
                text=f"Member {member['id']}",
                text_color=PALETTE["accent"],
                font=ctk.CTkFont(size=12, weight="bold"),
            ).pack(anchor="w", padx=16, pady=(14, 0))
            ctk.CTkLabel(card, text=member["name"], font=ctk.CTkFont(size=18, weight="bold")).pack(
                anchor="w", padx=16
            )
            ctk.CTkLabel(card, text=member["role"], text_color=PALETTE["muted"]).pack(
                anchor="w", padx=16, pady=(0, 14)
            )

        thanks = Card(self)
        thanks.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        ctk.CTkLabel(thanks, text="Thank you", font=ctk.CTkFont(size=18, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 4)
        )
        ctk.CTkLabel(
            thanks,
            text="Questions: replace this line with a team email. Edit names and college in config.py.",
            text_color=PALETTE["muted"],
        ).pack(anchor="w", padx=18, pady=(0, 16))
