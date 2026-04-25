import subprocess, sys, time

start = time.time()
print(f"[*] Starting Slither on v4-periphery...", flush=True)

try:
    r = subprocess.run(
        [
            "D:/Python/Scripts/slither.exe", ".",
            "--json", "-",
            "--compile-force-framework", "foundry",
            "--foundry-ignore-compile",
            "--foundry-out-directory", "foundry-out",
            "--filter-paths", "test,script,node_modules,.git,lib",
        ],
        cwd=r"z:\Sentinal Engine\v4-periphery",
        capture_output=True,
        text=True,
        timeout=300,
    )
    elapsed = time.time() - start
    print(f"[*] Slither finished in {elapsed:.1f}s", flush=True)
    print(f"[*] Return code: {r.returncode}", flush=True)
    print(f"[*] STDOUT length: {len(r.stdout)} chars", flush=True)
    print(f"[*] STDERR length: {len(r.stderr)} chars", flush=True)
    
    if r.stdout:
        # Check if JSON was produced
        idx = r.stdout.find('{')
        print(f"[*] First '{{' at index: {idx}", flush=True)
        if idx >= 0:
            print(f"[*] JSON starts with: {r.stdout[idx:idx+200]}", flush=True)
        else:
            print(f"[*] STDOUT (first 1000): {r.stdout[:1000]}", flush=True)
    else:
        print("[!] STDOUT is empty!", flush=True)
    
    if r.stderr:
        print(f"[*] STDERR (first 2000):", flush=True)
        print(r.stderr[:2000], flush=True)
    else:
        print("[*] STDERR is empty", flush=True)

except subprocess.TimeoutExpired:
    elapsed = time.time() - start
    print(f"[!] Slither timed out after {elapsed:.1f}s", flush=True)
except Exception as e:
    print(f"[!] Error: {e}", flush=True)
