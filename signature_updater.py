"""Signature and threat intelligence database updater for Counterscarp Engine."""

import json
import os
import shutil
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    import requests as _requests
except ImportError:  # pragma: no cover
    _requests = None  # type: ignore

logger = logging.getLogger("counterscarp.signature_updater")


def update_all_signatures(config=None) -> Dict[str, int]:
    """Update bundled threat intelligence and protocol signature databases.

    Returns dict with counts:
        {"threat_intel_updated": N, "protocols_updated": M}
    """
    results = {"threat_intel_updated": 0, "protocols_updated": 0}

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Update threat intelligence database
    threat_db_path = os.path.join(base_dir, "data", "threat_intel_db.json")
    results["threat_intel_updated"] = _update_threat_intel(
        threat_db_path, config
    )

    # 2. Update protocol signatures (refresh count)
    proto_db_path = os.path.join(
        base_dir, "data", "protocol_fingerprints.json"
    )
    results["protocols_updated"] = _refresh_protocol_db(proto_db_path)

    # Print summary
    sep = "=" * 60
    print(f"\n{sep}")
    print("  Signature Update Complete")
    print(sep)
    print(f"  Threat Intel entries updated: {results['threat_intel_updated']}")
    print(f"  Protocol signatures:          {results['protocols_updated']}")
    print(f"  Timestamp:                    {datetime.now().isoformat()}")
    print(f"{sep}\n")

    return results


def _update_threat_intel(db_path: str, config=None) -> int:
    """Fetch latest threat intel from C4 and Immunefi, merge with DB."""
    print("\n[1/2] Updating threat intelligence database...")

    # Load existing DB — handles both bare-array and wrapped-object schemas
    existing_entries = []
    db_wrapper = None
    if os.path.exists(db_path):
        with open(db_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict) and "entries" in raw:
            db_wrapper = raw
            existing_entries = raw["entries"]
        elif isinstance(raw, list):
            existing_entries = raw
        else:
            existing_entries = []

    existing_ids = {e["id"] for e in existing_entries}
    new_entries = []

    # Try fetching from Code4rena
    try:
        from knowledge_fetcher import fetch_c4_findings
        c4_results = fetch_c4_findings(["smart contract vulnerability"])
        for item in c4_results:
            entry_id = f"C4-{abs(hash(item.get('title', ''))) % 100000:05d}"
            if entry_id not in existing_ids:
                new_entries.append({
                    "id": entry_id,
                    "title": item.get("title", "Unknown"),
                    "category": "External Intel",
                    "severity": item.get("severity", "MEDIUM"),
                    "description": (
                        item.get("description") or item.get("body", "")
                    ),
                    "affected_patterns": [],
                    "references": [
                        item.get("html_url") or item.get("url", "")
                    ],
                    "cve": None,
                    "last_updated": datetime.now().strftime("%Y-%m-%d"),
                })
        c4_new = len(new_entries)
        print(f"  Code4rena: fetched {len(c4_results)} items, {c4_new} new")
    except Exception as e:
        print(f"  Code4rena: unavailable ({e})")

    # Try fetching from Immunefi
    try:
        from knowledge_fetcher import fetch_immunefi_reports
        imm_results = fetch_immunefi_reports(["smart contract"])
        imm_new = 0
        for item in imm_results:
            entry_id = f"IMM-{abs(hash(item.get('title', ''))) % 100000:05d}"
            if entry_id not in existing_ids:
                new_entries.append({
                    "id": entry_id,
                    "title": item.get("title", "Unknown"),
                    "category": "External Intel",
                    "severity": item.get("severity", "HIGH"),
                    "description": item.get("description", ""),
                    "affected_patterns": [],
                    "references": [item.get("url", "")],
                    "cve": None,
                    "last_updated": datetime.now().strftime("%Y-%m-%d"),
                })
                imm_new += 1
        print(f"  Immunefi:  fetched {len(imm_results)} items, {imm_new} new")
    except Exception as e:
        print(f"  Immunefi:  unavailable ({e})")

    # Merge and save
    if new_entries:
        existing_entries.extend(new_entries)
        payload: Any
        if db_wrapper is not None:
            db_wrapper["entries"] = existing_entries
            db_wrapper["last_updated"] = datetime.now().strftime("%Y-%m-%d")
            payload = db_wrapper
        else:
            payload = existing_entries
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"  Saved {len(existing_entries)} total entries to {db_path}")
    else:
        total = len(existing_entries)
        print(f"  No new entries found. Database unchanged ({total} entries).")

    return len(new_entries)


def _refresh_protocol_db(db_path: str) -> int:
    """Refresh protocol signature database metadata."""
    print("\n[2/2] Refreshing protocol signature database...")

    if not os.path.exists(db_path):
        print(f"  Protocol database not found at {db_path}")
        return 0

    with open(db_path, "r", encoding="utf-8") as f:
        protocols = json.load(f)

    if isinstance(protocols, list):
        count = len(protocols)
    else:
        count = len(protocols.get("protocols", protocols))
    print(f"  Protocol signatures: {count} protocols loaded")
    print(
        "  (Community signatures in data/community_signatures/ "
        "are loaded automatically)"
    )

    return count


# ---------------------------------------------------------------------------
# GitHub-pull updater (online mode)
# ---------------------------------------------------------------------------

GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/RunTimeAdmin/counterscarp-engine/main/data"
)

_FILES_TO_UPDATE = {
    "threat_intel_db.json": f"{GITHUB_RAW_BASE}/threat_intel_db.json",
    "protocol_fingerprints.json": f"{GITHUB_RAW_BASE}/protocol_fingerprints.json",
}


def update_from_github(data_dir: str = "data") -> Tuple[List[str], List[str]]:
    """Pull latest threat intelligence from GitHub raw content.

    Returns:
        (updated, failed) — lists of filenames that succeeded / failed.
    """
    if _requests is None:
        print("  Error: 'requests' library is not installed. "
              "Run: pip install requests")
        return [], list(_FILES_TO_UPDATE.keys())

    os.makedirs(data_dir, exist_ok=True)
    updated: List[str] = []
    failed: List[str] = []

    for filename, url in _FILES_TO_UPDATE.items():
        target_path = os.path.join(data_dir, filename)
        print(f"  Fetching {filename}...")
        try:
            response = _requests.get(url, timeout=30)
            response.raise_for_status()

            # Validate it's valid JSON before writing
            data = response.json()

            # Back up existing file
            if os.path.exists(target_path):
                backup_path = target_path + ".bak"
                shutil.copy2(target_path, backup_path)

            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            print(f"  \u2713 {filename}: updated successfully")
            updated.append(filename)
        except _requests.exceptions.RequestException as e:
            print(f"  \u2717 Failed to fetch {filename}: {e}")
            failed.append(filename)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"  \u2717 Invalid JSON from {filename}: {e}")
            failed.append(filename)

    return updated, failed


# ---------------------------------------------------------------------------
# Offline / local-file importer
# ---------------------------------------------------------------------------

def update_from_file(source_path: str, data_dir: str = "data") -> bool:
    """Import threat intelligence from a pre-downloaded JSON file.

    The target database is determined automatically from the file's content.
    """
    if not os.path.exists(source_path):
        print(f"Error: File not found: {source_path}")
        return False

    try:
        with open(source_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Determine target based on top-level keys
        if "entries" in data or "vulnerabilities" in data:
            target = os.path.join(data_dir, "threat_intel_db.json")
        elif "protocols" in data or "fingerprints" in data or isinstance(data, list):
            target = os.path.join(data_dir, "protocol_fingerprints.json")
        else:
            # Default to threat intel
            target = os.path.join(data_dir, "threat_intel_db.json")

        os.makedirs(data_dir, exist_ok=True)

        # Backup existing
        if os.path.exists(target):
            shutil.copy2(target, target + ".bak")

        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"Imported {source_path} \u2192 {target}")
        return True
    except Exception as e:
        print(f"Import failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Data freshness check
# ---------------------------------------------------------------------------

def check_data_freshness(data_dir: str = "data", warn_days: int = 90) -> None:
    """Check if bundled threat intel databases are outdated and warn if stale."""
    for filename in ["threat_intel_db.json", "protocol_fingerprints.json"]:
        filepath = os.path.join(data_dir, filename)
        if not os.path.exists(filepath):
            print(f"  \u26a0 {filename}: not found")
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support various timestamp field names
            last_updated = (
                data.get("last_updated")
                or data.get("updated_at")
                or data.get("timestamp")
            )
            if last_updated:
                updated_dt = datetime.fromisoformat(
                    last_updated.replace("Z", "+00:00")
                )
                # Make both naive or both aware
                now = (
                    datetime.now(tz=timezone.utc)
                    if updated_dt.tzinfo is not None
                    else datetime.now()
                )
                age_days = (now - updated_dt).days
                if age_days > warn_days:
                    print(
                        f"  \u26a0 {filename}: {age_days} days old "
                        f"(consider running --update-signatures)"
                    )
                else:
                    print(f"  \u2713 {filename}: {age_days} days old")
            else:
                print(f"  \u2014 {filename}: no timestamp found")
        except Exception:
            pass
