"""Launcher script for Ethernaut v3.1.2 full battery scan."""
import subprocess
import sys
import os

os.environ["PATH"] = os.environ.get("PATH", "") + r";z:\Sentinal Engine\foundry-bin"

result = subprocess.run(
    [
        sys.executable,
        r"z:\Sentinal Engine\sentinel-engine\orchestrator.py",
        "--target", r"z:\Sentinal Engine\ethernaut\contracts\src\levels",
        "--report",
        "--project-name", "Ethernaut v3.1.2 Full Battery",
    ],
    cwd=r"z:\Sentinal Engine\sentinel-engine",
    capture_output=False,
    text=True,
)
print(f"\n\nEXIT CODE: {result.returncode}")
sys.exit(result.returncode)
