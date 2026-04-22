#!/usr/bin/env python3
"""Do git add + commit for the rebranded files."""
import subprocess
import os

os.chdir(r"z:\Sentinal Engine\sentinel-engine")

files = [
    "orchestrator.py", "license_manager.py", "report_generator.py",
    "logger.py", "state_manager.py", "signature_updater.py",
    "rag_engine.py", "plugin_manager.py", "pipeline_generator.py",
    "heuristic_scanner.py", "red_team_scan.py", "attack_graph.py",
    "exploit_generator.py", "history_scanner.py", "fingerprint_scanner.py",
    "supply_chain_check.py", "fork_logic_checks.py", "access_matrix.py",
    "intent_check.py", "upgrade_diff.py", "solana_analyzer.py",
    "solana_intel.py", "threat_intel.py", "embeddings.py", "visualizer.py",
    "idl_validator.py", "protocol_db.py", "healthcheck.py",
    "knowledge_fetcher.py", "http_utils.py", "gui.py",
    "aderyn_wrapper.py", "medusa_wrapper.py", "symbolic_wrapper.py",
    "fuzz_wrapper.py", "exceptions.py", "config_loader.py",
]

# git add
result = subprocess.run(["git", "add"] + files, capture_output=True, text=True)
print("ADD stdout:", result.stdout)
print("ADD stderr:", result.stderr)
print("ADD rc:", result.returncode)

# git status
result = subprocess.run(["git", "status", "--short"], capture_output=True, text=True)
print("STATUS:", result.stdout[:2000])

# git commit
result = subprocess.run(
    ["git", "commit", "-m", "refactor: rebrand core Python modules to Counterscarp Engine"],
    capture_output=True, text=True
)
print("COMMIT stdout:", result.stdout)
print("COMMIT stderr:", result.stderr)
print("COMMIT rc:", result.returncode)

# git log
result = subprocess.run(["git", "log", "--oneline", "-3"], capture_output=True, text=True)
print("LOG:", result.stdout)
