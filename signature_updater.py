"""Signature and threat intelligence database updater for Sentinel Engine."""

import json
import os
import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger("sentinel.signature_updater")


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
