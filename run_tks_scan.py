import subprocess
import sys
import os

os.environ["PATH"] = os.environ.get("PATH", "") + r";z:\Sentinal Engine\foundry-bin"
os.chdir(r"z:\Sentinal Engine\sentinel-engine")

outfile = r"z:\Sentinal Engine\tks_scan_output.txt"
with open(outfile, "w", encoding="utf-8") as f:
    result = subprocess.run(
        [sys.executable, "orchestrator.py",
         "--target", r"z:\Sentinal Engine\tokenkickstarter\smart-contracts",
         "--report",
         "--project-name", "TokenKickstarter Security Audit"],
        stdout=f, stderr=subprocess.STDOUT
    )

with open(outfile, "a", encoding="utf-8") as f:
    f.write(f"\n=== EXIT CODE: {result.returncode} ===")

print(f"Done. Exit code: {result.returncode}")
print(f"Output saved to: {outfile}")
