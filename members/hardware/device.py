"""Member 5 — Hardware (ESP32 / RFID stretch). Support to/from Members 2 and 3.

UI only talks to HardwareBridge. Swap the body for real serial I/O.
"""

from __future__ import annotations

from core.contracts import HardwareStatus


class HardwareBridge:
    def __init__(self, port: str = "COM3", baud: int = 115200) -> None:
        self.port = port
        self.baud = baud
        self._connected = False
        self._last = ""

    def connect(self) -> HardwareStatus:
        try:
            import serial  # type: ignore

            ser = serial.Serial(self.port, self.baud, timeout=1)
            ser.close()
            self._connected = True
            return HardwareStatus(
                connected=True,
                port=self.port,
                message=f"Opened {self.port} @ {self.baud} baud",
            )
        except Exception:
            self._connected = False
            return HardwareStatus(
                connected=False,
                port=self.port,
                message="ESP32 not found — UI is ready; Member 5 can attach serial later.",
            )

    def disconnect(self) -> HardwareStatus:
        self._connected = False
        return HardwareStatus(connected=False, port=self.port, message="Disconnected")

    def poll(self) -> HardwareStatus:
        return HardwareStatus(
            connected=self._connected,
            port=self.port,
            last_payload=self._last,
            message="Listening for QR/URL payloads from ESP32" if self._connected else "Idle",
        )

    def inject_demo_payload(self, url: str) -> str:
        """Used by the UI demo button until firmware is ready."""
        self._last = url
        self._connected = True
        return url
