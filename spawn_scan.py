"""Spawn scan process detached from parent terminal."""
import subprocess
import sys
import os
import time

FOUNDRY_BIN = r"z:\Sentinal Engine\foundry-bin"
WORKING_DIR = r"z:\Sentinal Engine\sentinel-engine"
OUTPUT_FILE = r"z:\Sentinal Engine\sentinel-engine\ethernaut_v312_out.txt"

env = dict(os.environ)
if FOUNDRY_BIN not in env.get("PATH", ""):
    env["PATH"] = env.get("PATH", "") + ";" + FOUNDRY_BIN

cmd = [
    sys.executable,
    r"z:\Sentinal Engine\sentinel-engine\orchestrator.py",
    "--target", r"z:\Sentinal Engine\ethernaut\contracts\src\levels",
    "--report",
    "--project-name", "Ethernaut v3.1.2 Full Battery",
]

print(f"Spawning scan process...")
print(f"Output -> {OUTPUT_FILE}")

with open(OUTPUT_FILE, "w", encoding="utf-8") as out_fh:
    proc = subprocess.Popen(
        cmd,
        cwd=WORKING_DIR,
        env=env,
        stdout=out_fh,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

print(f"PID: {proc.pid}")
print(f"Waiting for completion...")
ret = proc.wait()
print(f"Exit code: {ret}")
print(f"Output written to: {OUTPUT_FILE}")
