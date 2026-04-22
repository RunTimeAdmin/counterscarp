#!/usr/bin/env python3
"""
One-shot rebrand script: Garrison → Counterscarp for all core Python modules.
Run from the sentinel-engine directory.
"""
import os
import re

# Ordered replacements - most specific first to avoid partial replacements
REPLACEMENTS = [
    # Exact env vars
    ("GARRISON_PRO_LICENSE", "COUNTERSCARP_PRO_LICENSE"),
    ("GARRISON_LOG_LEVEL", "COUNTERSCARP_LOG_LEVEL"),
    ("GARRISON_LOG_FORMAT", "COUNTERSCARP_LOG_FORMAT"),
    ("GARRISON_LOG_FILE", "COUNTERSCARP_LOG_FILE"),
    # Class names
    ("GarrisonAnalysisError", "CounterscarpAnalysisError"),
    ("GarrisonReportError", "CounterscarpReportError"),
    ("GarrisonConfigError", "CounterscarpConfigError"),
    ("GarrisonScanError", "CounterscarpScanError"),
    ("GarrisonLicenseError", "CounterscarpLicenseError"),
    ("GarrisonPluginError", "CounterscarpPluginError"),
    ("GarrisonError", "CounterscarpError"),
    ("GarrisonConfig", "CounterscarpConfig"),
    ("is_garrison_error", "is_counterscarp_error"),
    # JSON encoder class
    ("_GarrisonJSONEncoder", "_CounterscarpJSONEncoder"),
    # Logger names that use "garrison." prefix
    ('logging.getLogger("garrison.', 'logging.getLogger("counterscarp.'),
    ("logging.getLogger('garrison.", "logging.getLogger('counterscarp."),
    ('get_logger("garrison.', 'get_logger("counterscarp.'),
    ("get_logger('garrison.", "get_logger('counterscarp."),
    # Paths and files
    (".garrison/", ".counterscarp/"),
    ('".garrison"', '".counterscarp"'),
    ("'.garrison'", "'.counterscarp'"),
    ("/ '.garrison'", "/ '.counterscarp'"),
    ('/ ".garrison"', '/ ".counterscarp"'),
    ("garrison.toml", "counterscarp.toml"),
    ("garrison_scan_", "counterscarp_scan_"),
    # URLs and domains
    ("api.garrisonsec.com", "api.counterscarp.io"),
    ("app.garrisonsec.com", "app.counterscarp.io"),
    ("garrisonsec.com", "counterscarp.io"),
    ("support@counterscarp.io", "contact@counterscarp.io"),  # fix Task 107 stale
    ("support@garrisonsec.com", "contact@counterscarp.io"),
    ("help@protocol14019.com", "contact@counterscarp.io"),
    # GitHub URL
    ("github.com/RunTimeAdmin/garrison-engine", "github.com/RunTimeAdmin/counterscarp"),
    # Package name strings
    ("garrison-engine", "counterscarp-engine"),
    ("garrison_engine", "counterscarp_engine"),
    # Brand name strings (case-sensitive order: full phrase first)
    ("Garrison Security Engine", "Counterscarp Security Engine"),
    ("Garrison Engine", "Counterscarp Engine"),
    ("garrison engine", "counterscarp engine"),
    # Cache/home dir references
    ('Path.home() / ".garrison"', 'Path.home() / ".counterscarp"'),
    # Remaining bare references
    ("GARRISON", "COUNTERSCARP"),
    ("Garrison", "Counterscarp"),
    ("garrison", "counterscarp"),
]

TARGET_FILES = [
    "orchestrator.py",
    "license_manager.py",
    "report_generator.py",
    "logger.py",
    "state_manager.py",
    "signature_updater.py",
    "rag_engine.py",
    "plugin_manager.py",
    "pipeline_generator.py",
    "heuristic_scanner.py",
    "red_team_scan.py",
    "attack_graph.py",
    "exploit_generator.py",
    "history_scanner.py",
    "fingerprint_scanner.py",
    "supply_chain_check.py",
    "fork_logic_checks.py",
    "access_matrix.py",
    "intent_check.py",
    "upgrade_diff.py",
    "solana_analyzer.py",
    "solana_intel.py",
    "threat_intel.py",
    "embeddings.py",
    "visualizer.py",
    "idl_validator.py",
    "protocol_db.py",
    "healthcheck.py",
    "knowledge_fetcher.py",
    "http_utils.py",
    "gui.py",
    "aderyn_wrapper.py",
    "medusa_wrapper.py",
    "symbolic_wrapper.py",
    "fuzz_wrapper.py",
    "exceptions.py",
    "config_loader.py",
]

base_dir = os.path.dirname(os.path.abspath(__file__))

changed = []
unchanged = []
missing = []

for fname in TARGET_FILES:
    fpath = os.path.join(base_dir, fname)
    if not os.path.exists(fpath):
        missing.append(fname)
        continue

    with open(fpath, "r", encoding="utf-8") as f:
        original = f.read()

    content = original
    for old, new in REPLACEMENTS:
        content = content.replace(old, new)

    if content != original:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        changed.append(fname)
    else:
        unchanged.append(fname)

print("=== CHANGED ===")
for fname_c in changed:
    print(f"  [+] {fname_c}")

print("\n=== UNCHANGED (no garrison refs) ===")
for fname_u in unchanged:
    print(f"  [-] {fname_u}")

if missing:
    print("\n=== MISSING (file not found) ===")
    for fname_m in missing:
        print(f"  [!] {fname_m}")

print(f"\nDone. {len(changed)} files updated, {len(unchanged)} had no garrison refs, {len(missing)} missing.")
