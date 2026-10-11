"""Reusable cards, chips, and metric tiles."""

from __future__ import annotations

import customtkinter as ctk

from ui.theme import PALETTE, verdict_color


class Card(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", PALETTE["card"])
        kwargs.setdefault("corner_radius", 16)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", PALETTE["line"])
        super().__init__(master, **kwargs)


class HoverButton(ctk.CTkButton):
    """Button with a pointer cursor and a crisp security-console hover cue."""
    def __init__(self, master, **kwargs):
        kwargs.setdefault("cursor", "hand2")
        kwargs.setdefault("corner_radius", 10)
        super().__init__(master, **kwargs)
        # CTkButton renders through an internal canvas.  Set its cursor too;
        # setting only the wrapper does not reliably affect Windows pointer UI.
        self._canvas.configure(cursor="hand2")
        if hasattr(self, "_text_label") and self._text_label:
            self._text_label.configure(cursor="hand2")
        self.bind("<Enter>", lambda _event: self.configure(border_width=1, border_color=PALETTE["accent"]), add="+")
        self.bind("<Leave>", lambda _event: self.configure(border_width=0), add="+")


class MetricTile(Card):
    def __init__(self, master, title: str, value: str, hint: str = "", accent: str | None = None):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=title.upper(),
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 0))
        self.value_lbl = ctk.CTkLabel(
            self,
            text=value,
            text_color=accent or PALETTE["text"],
            font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
        )
        self.value_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(4, 0))
        self.hint_lbl = ctk.CTkLabel(
            self,
            text=hint,
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
        )
        self.hint_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 14))

    def set(self, value: str, hint: str | None = None) -> None:
        self.value_lbl.configure(text=value)
        if hint is not None:
            self.hint_lbl.configure(text=hint)


class ReasonChip(ctk.CTkFrame):
    def __init__(self, master, text: str, tone: str = "muted"):
        color = {
            "safe": PALETTE["accent_dim"],
            "malicious": "#3A1520",
            "suspicious": "#3A2E10",
            "muted": PALETTE["card_alt"],
        }.get(tone, PALETTE["card_alt"])
        super().__init__(master, fg_color=color, corner_radius=10)
        ctk.CTkLabel(
            self,
            text=text,
            text_color=PALETTE["text"],
            font=ctk.CTkFont(size=12),
            wraplength=520,
            justify="left",
        ).pack(padx=10, pady=8, anchor="w")


class VerdictBadge(ctk.CTkFrame):
    def __init__(self, master, label: str = "unknown", confidence: float = 0.0):
        super().__init__(master, fg_color="transparent")
        self.pill = ctk.CTkLabel(
            self,
            text=label.upper(),
            fg_color=verdict_color(label),
            text_color="#071014",
            corner_radius=999,
            font=ctk.CTkFont(size=14, weight="bold"),
            width=140,
            height=32,
        )
        self.pill.pack(side="left")
        self.conf = ctk.CTkLabel(
            self,
            text=f"{confidence:.0%} confidence",
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(size=13),
        )
        self.conf.pack(side="left", padx=12)

    def set(self, label: str, confidence: float) -> None:
        self.pill.configure(text=label.upper(), fg_color=verdict_color(label))
        self.conf.configure(text=f"{confidence:.0%} confidence")


class SignalTile(ctk.CTkFrame):
    def __init__(self, master, label: str, value: str = "--"):
        super().__init__(master, fg_color=PALETTE["card_alt"], corner_radius=10)
        ctk.CTkLabel(self, text=label.upper(), text_color=PALETTE["muted"], font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=12, pady=(9, 0))
        self.value = ctk.CTkLabel(self, text=value, text_color=PALETTE["text"], font=ctk.CTkFont(size=16, weight="bold"))
        self.value.pack(anchor="w", padx=12, pady=(1, 9))

    def set(self, value: str, color: str | None = None) -> None:
        self.value.configure(text=value, text_color=color or PALETTE["text"])
