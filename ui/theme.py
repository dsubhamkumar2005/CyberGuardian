"""Visual system for CyberGuardian Desk — dark SOC console, not a generic admin theme."""

from __future__ import annotations

import customtkinter as ctk

PALETTE = {
    "bg": "#070B14",
    "sidebar": "#0C1220",
    "card": "#121A2C",
    "card_alt": "#182238",
    "line": "#243049",
    "text": "#E8EEF9",
    "muted": "#8B9BB8",
    "accent": "#2EE6A6",
    "accent_dim": "#163A30",
    "cyan": "#4CC9F0",
    "safe": "#2EE6A6",
    "suspicious": "#F5C542",
    "malicious": "#FF4D6D",
    "unknown": "#8B9BB8",
}


def apply_theme() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


def verdict_color(label: str) -> str:
    return PALETTE.get(label, PALETTE["unknown"])
