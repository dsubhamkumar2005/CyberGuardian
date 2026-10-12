"""Launch CyberGuardian Desk (Member 1 UI)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ui.main_window import launch

if __name__ == "__main__":
    launch()
