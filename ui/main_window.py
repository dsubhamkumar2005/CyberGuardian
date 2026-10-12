"""Member 1 — Desktop Application & UI Lead (support from Member 4)."""

from __future__ import annotations

import sys
import random
from pathlib import Path

# Allow `python run.py` from repo root or this folder.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import customtkinter as ctk

from config import APP_NAME, CLIPBOARD_POLL_MS, TEAM_NAME
from core.contracts import ScanRequest, ScanResult
from core.pipeline import GuardianPipeline
from core.adapters import InputProcessor
from ui.pages.analytics import AnalyticsPage
from ui.pages.dashboard import DashboardPage
from ui.pages.history import HistoryPage
from ui.pages.scan import ScanPage
from ui.theme import PALETTE, apply_theme, verdict_color
from ui.widgets import HoverButton


NAV = [
    ("Dashboard", "dashboard"),
    ("Scan", "scan"),
    ("History", "history"),
    ("Analytics", "analytics"),
]


class AlertToast(ctk.CTkToplevel):
    def __init__(self, master, result: ScanResult):
        super().__init__(master)
        self.title("CyberGuardian alert")
        self.geometry("420x180")
        self.configure(fg_color=PALETTE["card"])
        self.attributes("-topmost", True)

        color = verdict_color(result.verdict.value)

        ctk.CTkLabel(
            self,
            text=result.verdict.value.upper(),
            text_color=color,
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(18, 4))

        ctk.CTkLabel(
            self,
            text=result.extracted.url,
            wraplength=380,
            justify="left",
            text_color=PALETTE["text"],
        ).pack(anchor="w", padx=20)

        why = (
            result.reasons[0]
            if result.reasons
            else "See the Scan page for reasons."
        )

        ctk.CTkLabel(
            self,
            text=why,
            wraplength=380,
            justify="left",
            text_color=PALETTE["muted"],
        ).pack(anchor="w", padx=20, pady=(8, 16))

        self.after(6000, self.destroy)


class MainWindow(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        apply_theme()

        self.title(f"{APP_NAME} — {TEAM_NAME}")
        self.geometry("1180x740")
        self.minsize(980, 640)
        self.configure(fg_color=PALETTE["bg"])

        self._build_ambient_background()

        self.pipeline = GuardianPipeline()
        self.clipboard_on = False
        self._last_clip = ""
        self.pages: dict[str, ctk.CTkFrame] = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_pages()

        self.show("dashboard")

        self.after(CLIPBOARD_POLL_MS, self._poll_clipboard)

    def _build_ambient_background(self) -> None:
        self.ambient = ctk.CTkCanvas(
            self,
            bg=PALETTE["bg"],
            highlightthickness=0
        )

        self.ambient.place(
            x=0,
            y=0,
            relwidth=1,
            relheight=1
        )

        self._ambient_points = [
            (
                random.randint(0, 1200),
                random.randint(0, 740),
                random.choice((1, -1))
            )
            for _ in range(28)
        ]

        self.bind(
            "<Configure>",
            lambda _event: self._draw_ambient(),
            add="+"
        )

        self.after(80, self._animate_ambient)

    def _draw_ambient(self) -> None:
        canvas = self.ambient
        canvas.delete("all")

        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)

        for x in range(0, width, 52):
            canvas.create_line(
                x,
                0,
                x,
                height,
                fill="#0A1525"
            )

        for y in range(0, height, 52):
            canvas.create_line(
                0,
                y,
                width,
                y,
                fill="#0A1525"
            )

        for x, y, _direction in self._ambient_points:
            canvas.create_oval(
                x - 2,
                y - 2,
                x + 2,
                y + 2,
                fill="#1B8067",
                outline=""
            )

    def _animate_ambient(self) -> None:
        width = max(self.ambient.winfo_width(), 1)
        height = max(self.ambient.winfo_height(), 1)

        self._ambient_points = [
            (
                (x + direction) % width,
                (y + direction) % height,
                direction
            )
            for x, y, direction in self._ambient_points
        ]

        self._draw_ambient()

        self.after(80, self._animate_ambient)

    def _build_sidebar(self) -> None:
        side = ctk.CTkFrame(
            self,
            width=220,
            fg_color=PALETTE["sidebar"],
            corner_radius=0
        )

        side.grid(
            row=0,
            column=0,
            sticky="nsw"
        )

        side.grid_propagate(False)

        ctk.CTkLabel(
            side,
            text="CG",
            fg_color=PALETTE["accent"],
            text_color="#071014",
            width=44,
            height=44,
            corner_radius=12,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(
            padx=18,
            pady=(22, 8),
            anchor="w"
        )

        ctk.CTkLabel(
            side,
            text=APP_NAME,
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(
            padx=18,
            anchor="w"
        )

        ctk.CTkLabel(
            side,
            text="On-device · no cloud",
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(size=12)
        ).pack(
            padx=18,
            pady=(0, 18),
            anchor="w"
        )

        self.nav_buttons: dict[str, ctk.CTkButton] = {}

        for label, key in NAV:
            btn = HoverButton(
                side,
                text=label,
                fg_color="transparent",
                hover_color=PALETTE["card"],
                anchor="w",
                height=38,
                command=lambda k=key: self.show(k),
            )

            btn.pack(
                fill="x",
                padx=12,
                pady=2
            )

            self.nav_buttons[key] = btn

        self.clip_switch = ctk.CTkSwitch(
            side,
            text="Watch clipboard",
            command=self._toggle_clip,
            cursor="hand2"
        )

        self.clip_switch.pack(
            padx=18,
            pady=(24, 8),
            anchor="w"
        )

        self.clip_hint = ctk.CTkLabel(
            side,
            text="Passive · local only",
            text_color=PALETTE["muted"],
            font=ctk.CTkFont(size=11)
        )

        self.clip_hint.pack(
            padx=18,
            anchor="w"
        )

    def _build_pages(self) -> None:
        host = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        host.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=22,
            pady=18
        )

        host.grid_columnconfigure(0, weight=1)
        host.grid_rowconfigure(0, weight=1)

        self.pages["dashboard"] = DashboardPage(
            host,
            self.pipeline,
            on_goto_scan=lambda: self.show("scan")
        )

        self.pages["scan"] = ScanPage(
            host,
            self.pipeline,
            on_alert=self._on_scan_done
        )

        self.pages["history"] = HistoryPage(
            host,
            self.pipeline
        )

        self.pages["analytics"] = AnalyticsPage(
            host,
            self.pipeline
        )

        for page in self.pages.values():
            page.grid(
                row=0,
                column=0,
                sticky="nsew"
            )

    def show(self, key: str) -> None:
        page = self.pages[key]
        page.tkraise()

        for k, btn in self.nav_buttons.items():
            btn.configure(
                fg_color=PALETTE["card"]
                if k == key
                else "transparent"
            )

        if key == "dashboard":
            self.pages["dashboard"].refresh(
                self.clipboard_on
            )

        elif key == "history":
            self.pages["history"].refresh()

        elif key == "analytics":
            self.pages["analytics"].refresh()
            self.after(
                80,
                self.pages["analytics"].refresh
            )

    def _toggle_clip(self) -> None:
        self.clipboard_on = bool(
            self.clip_switch.get()
        )

        if hasattr(
            self.pages["dashboard"],
            "refresh"
        ):
            self.pages["dashboard"].refresh(
                self.clipboard_on
            )

    def _poll_clipboard(self) -> None:
        if self.clipboard_on:
            try:
                text = self.clipboard_get()
            except Exception:
                text = ""

            if text and text != self._last_clip:
                self._last_clip = text

                url = InputProcessor().extract_url_from_clipboard(text)

                if url:
                    result = self.pipeline.scan(
                        ScanRequest(
                            source="clipboard",
                            raw_input=url
                        )
                    )

                    self.pages["scan"].show_result(result)
                    self._on_scan_done(result)
                    self.show("scan")

        self.after(
            CLIPBOARD_POLL_MS,
            self._poll_clipboard
        )

    def _on_scan_done(self, result: ScanResult) -> None:
        self.pages["scan"].show_result(result)

        if result.verdict.value in {
            "malicious",
            "suspicious"
        }:
            AlertToast(self, result)

        self.pages["dashboard"].refresh(
            self.clipboard_on
        )


def launch() -> None:
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    launch()