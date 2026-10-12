"""App-wide settings. Safe to edit; no secrets required."""

from pathlib import Path

APP_NAME = "CyberGuardian Desk"
APP_VERSION = "0.1.0"
TEAM_NAME = "Team CyberGuardian"
COLLEGE_NAME = "Your College Name"
DOMAIN = "Cybersecurity"

# Fill in real names for the title / team slides.
TEAM = [
    {"id": 1, "name": "Member 1", "role": "Desktop Application & UI Lead"},
    {"id": 2, "name": "Member 2", "role": "AI/ML Lead"},
    {"id": 3, "name": "Member 3", "role": "Input Processing & Security"},
    {"id": 4, "name": "Member 4", "role": "Backend & Security Analytics Lead"},
    {"id": 5, "name": "Member 5", "role": "Hardware Integration"},
]

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "cyberguardian.sqlite"

# Privacy defaults — local only. Network stays off unless the user opts in.
CLIPBOARD_POLL_MS = 900
HIBP_ENABLED_DEFAULT = False
HARDWARE_PORT_DEFAULT = "COM3"
HARDWARE_BAUD_DEFAULT = 115200
