"""Runs the SAFE sandbox simulation script on behalf of the dashboard buttons."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "data" / "sandbox"
MODES = ("attack", "normal", "zip")


class Simulator:
    """Starts scripts/simulate_attack.py (sandbox only) and can clean the sandbox."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, mode: str) -> bool:
        """Launch a simulation; returns False if one is already running or the mode is unknown."""
        if mode not in MODES or self.running:
            return False
        self._proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "simulate_attack.py"), mode], cwd=ROOT)
        return True

    def reset(self) -> int:
        """Delete throwaway files directly inside data/sandbox ONLY. Returns how many were removed."""
        if self.running:
            return -1
        n = 0
        for f in SANDBOX.glob("*"):
            if f.is_file() and f.name != ".gitkeep":
                f.unlink(missing_ok=True)
                n += 1
        return n
