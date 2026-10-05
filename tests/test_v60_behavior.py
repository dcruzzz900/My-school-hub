"""Runs the end-to-end V60 scenarios (real HTTP requests against a fresh database) in a separate process."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v60_end_to_end_scenarios():
    proc = subprocess.run([sys.executable, str(ROOT / "tests" / "v60_scenarios.py")], capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
