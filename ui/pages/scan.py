"""Focused, presentation-ready link scanning workspace."""
from __future__ import annotations

from tkinter import filedialog
import customtkinter as ctk

from core.contracts import ScanRequest, ScanResult
from core.pipeline import GuardianPipeline
from ui.theme import PALETTE
from ui.widgets import Card, HoverButton, ReasonChip, VerdictBadge


FEATURES = (
    ("length", "URL length", "characters"),
    ("subdomain_count", "Subdomain count", "levels"),
    ("uses_ip", "IP address host", "yes / no"),
    ("has_https", "HTTPS enabled", "yes / no"),
    ("special_char_count", "Special characters", "characters"),
    ("shannon_entropy", "URL entropy", "bits"),
)


class ScanPage(ctk.CTkFrame):
    def __init__(self, master, pipeline: GuardianPipeline, on_alert, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.pipeline, self.on_alert, self.qr_path = pipeline, on_alert, None
        self.grid_columnconfigure(0, weight=5); self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(1, weight=1)
        self._build_header(); self._build_input(); self._build_report()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(header, text="Link Intelligence Console", font=ctk.CTkFont(size=25, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text="LOCAL ANALYSIS  •  NO CLOUD UPLOAD", text_color=PALETTE["accent"], font=ctk.CTkFont(size=11, weight="bold")).pack(side="right", pady=8)

    def _build_input(self):
        card = Card(self); card.grid(row=1, column=0, sticky="nsew", padx=(0, 8)); card.grid_rowconfigure(3, weight=1); card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text="1  •  INPUT", text_color=PALETTE["accent"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 2))
        ctk.CTkLabel(card, text="Inspect a suspicious link", font=ctk.CTkFont(size=19, weight="bold")).grid(row=1, column=0, sticky="w", padx=20)
        tabs = ctk.CTkTabview(card, fg_color=PALETTE["card"], segmented_button_selected_color=PALETTE["accent"], segmented_button_unselected_color=PALETTE["card_alt"])
        tabs.grid(row=2, column=0, sticky="ew", padx=18, pady=(14, 4)); tabs.add("Paste URL"); tabs.add("QR image")
        url_tab = tabs.tab("Paste URL")
        ctk.CTkLabel(url_tab, text="Paste a complete link. It is processed only on this computer.", text_color=PALETTE["muted"], wraplength=420, justify="left").pack(anchor="w", padx=8, pady=(10, 5))
        self.url_box = ctk.CTkTextbox(url_tab, height=150, fg_color=PALETTE["card_alt"], border_width=1, border_color=PALETTE["line"], font=ctk.CTkFont(size=14))
        self.url_box.pack(fill="x", padx=8, pady=(0, 8))
        self.url_status = ctk.CTkLabel(url_tab, text="SYSTEM READY", text_color=PALETTE["cyan"], font=ctk.CTkFont(size=11, weight="bold"), wraplength=420, justify="left"); self.url_status.pack(anchor="w", padx=8, pady=(0, 6))
        HoverButton(url_tab, text="RUN SECURITY ANALYSIS  →", fg_color=PALETTE["accent"], text_color="#071014", hover_color="#25c48d", height=44, command=self._scan_url).pack(fill="x", padx=8, pady=(0, 10))
        qr_tab = tabs.tab("QR image")
        ctk.CTkLabel(qr_tab, text="Select a QR image or paste the decoded destination.", text_color=PALETTE["muted"]).pack(anchor="w", padx=8, pady=(10, 8))
        self.qr_label = ctk.CTkLabel(qr_tab, text="No image selected", text_color=PALETTE["cyan"]); self.qr_label.pack(anchor="w", padx=8, pady=5)
        HoverButton(qr_tab, text="SELECT QR IMAGE", command=self._pick_qr).pack(fill="x", padx=8, pady=5)
        self.qr_fallback = ctk.CTkEntry(qr_tab, placeholder_text="Paste decoded QR URL"); self.qr_fallback.pack(fill="x", padx=8, pady=8)
        HoverButton(qr_tab, text="ANALYZE QR PAYLOAD  →", fg_color=PALETTE["cyan"], text_color="#071014", height=44, command=self._scan_qr).pack(fill="x", padx=8, pady=(0, 10))
        footer = ctk.CTkFrame(card, fg_color=PALETTE["card_alt"], corner_radius=10); footer.grid(row=4, column=0, sticky="ew", padx=18, pady=14)
        ctk.CTkLabel(footer, text="TIP", text_color=PALETTE["accent"], font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=12, pady=(9, 0))
        ctk.CTkLabel(footer, text="Check unexpected login, payment, delivery, and verification links before opening them.", text_color=PALETTE["muted"], wraplength=440, justify="left").pack(anchor="w", padx=12, pady=(1, 9))

    def _build_report(self):
        card = Card(self); card.grid(row=1, column=1, sticky="nsew", padx=(8, 0)); card.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(card, text="2  •  ANALYSIS REPORT", text_color=PALETTE["cyan"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(18, 2))
        self.badge = VerdictBadge(card, "unknown", 0); self.badge.grid(row=1, column=0, sticky="w", padx=20, pady=(3, 7))
        self.url_out = ctk.CTkLabel(card, text="No link scanned yet", text_color=PALETTE["muted"], wraplength=420, justify="left"); self.url_out.grid(row=2, column=0, columnspan=2, sticky="w", padx=20)
        self.model_out = ctk.CTkLabel(card, text="Waiting for input", text_color=PALETTE["muted"], font=ctk.CTkFont(size=11)); self.model_out.grid(row=3, column=0, columnspan=2, sticky="w", padx=20, pady=(3, 9))
        self.confidence_bar = ctk.CTkProgressBar(card, height=8, progress_color=PALETTE["accent"], fg_color=PALETTE["card_alt"]); self.confidence_bar.grid(row=4, column=0, columnspan=2, sticky="ew", padx=20); self.confidence_bar.set(0)
        ctk.CTkLabel(card, text="RISK SIGNALS", text_color=PALETTE["muted"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=5, column=0, columnspan=2, sticky="w", padx=20, pady=(15, 5))
        self.feature_values = {}
        for index, (key, title, unit) in enumerate(FEATURES):
            row, col = divmod(index, 2); tile = ctk.CTkFrame(card, fg_color=PALETTE["card_alt"], corner_radius=10)
            tile.grid(row=6 + row, column=col, sticky="ew", padx=(20 if col == 0 else 5, 5 if col == 0 else 20), pady=3)
            ctk.CTkLabel(tile, text=title.upper(), text_color=PALETTE["muted"], font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=11, pady=(8, 0))
            value = ctk.CTkLabel(tile, text="—", font=ctk.CTkFont(size=16, weight="bold")); value.pack(anchor="w", padx=11)
            ctk.CTkLabel(tile, text=unit, text_color=PALETTE["muted"], font=ctk.CTkFont(size=10)).pack(anchor="w", padx=11, pady=(0, 8)); self.feature_values[key] = value
        ctk.CTkLabel(card, text="EXPLANATION", text_color=PALETTE["muted"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=9, column=0, columnspan=2, sticky="w", padx=20, pady=(14, 4))
        self.reasons = ctk.CTkFrame(card, fg_color="transparent"); self.reasons.grid(row=10, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 16))

    def _scan_url(self):
        text = self.url_box.get("1.0", "end").strip()
        if text: self._run(ScanRequest(source="url", raw_input=text))

    def _pick_qr(self):
        path = filedialog.askopenfilename(title="QR image", filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")])
        if path: self.qr_path = path; self.qr_label.configure(text=path)

    def _scan_qr(self):
        raw = self.qr_fallback.get().strip()
        if raw or self.qr_path: self._run(ScanRequest(source="qr", raw_input=raw, image_path=self.qr_path))

    def _run(self, request):
        self.url_status.configure(text="ANALYZING LOCAL SIGNALS...", text_color=PALETTE["suspicious"]); self.update_idletasks()
        try:
            result = self.pipeline.scan(request)
        except Exception as exc:
            details = str(exc).strip() or repr(exc)
            self.url_status.configure(
                text=f"ANALYSIS FAILED ({type(exc).__name__}): {details}",
                text_color=PALETTE["malicious"],
            )
            return
        self.show_result(result)
        self.url_status.configure(text="ANALYSIS COMPLETE • SAVED LOCALLY", text_color=PALETTE["safe"]); self.on_alert(result)

    def show_result(self, result: ScanResult):
        values, color = result.features.values, PALETTE.get(result.verdict.value, PALETTE["accent"])
        self.badge.set(result.verdict.value, result.confidence); self.confidence_bar.set(result.confidence); self.confidence_bar.configure(progress_color=color)
        self.url_out.configure(text=result.extracted.url, text_color=PALETTE["text"]); self.model_out.configure(text=f"{result.request.source.upper()} SOURCE  •  {result.model_name}")
        for key, _title, _unit in FEATURES:
            value = values.get(key, 0)
            if key in {"uses_ip", "has_https"}: text = "YES" if value else "NO"
            elif key == "shannon_entropy": text = f"{value:.2f}"
            else: text = str(int(value))
            danger = (key == "uses_ip" and value) or (key == "has_https" and not value) or (key == "special_char_count" and value > 6) or (key == "shannon_entropy" and value > 4.0)
            self.feature_values[key].configure(text=text, text_color=PALETTE["malicious"] if danger else PALETTE["text"])
        for child in self.reasons.winfo_children(): child.destroy()
        for reason in result.reasons[:3]: ReasonChip(self.reasons, reason, tone=result.verdict.value).pack(fill="x", pady=3, padx=4)
