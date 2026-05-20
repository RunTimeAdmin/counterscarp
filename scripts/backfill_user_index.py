#!/usr/bin/env python3
"""Backfill per-user audit index files from historical audit directories."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "data" / "audits"
INDEX_DIR = ROOT / "data" / "user_audit_index"
INDEX_DIR.mkdir(parents=True, exist_ok=True)


def _safe_user_id(user_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", user_id)[:128]


def main() -> int:
    if not RESULTS_DIR.exists():
        print(f"No audit directory found at: {RESULTS_DIR}")
        return 0

    per_user: Dict[str, List[dict]] = {}

    for audit_dir in RESULTS_DIR.iterdir():
        if not audit_dir.is_dir():
            continue

        meta_path = audit_dir / "scan_meta.json"
        index_path = audit_dir / "scan_index.json"
        if not meta_path.exists():
            continue

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            idx = (
                json.loads(index_path.read_text(encoding="utf-8"))
                if index_path.exists()
                else {}
            )
        except (json.JSONDecodeError, OSError):
            continue

        owner = meta.get("owner_user_id")
        if not owner:
            continue
        user_id = str(owner)

        per_user.setdefault(user_id, []).append(
            {
                "audit_id": audit_dir.name,
                "project_name": idx.get(
                    "project_name",
                    meta.get("project_name", "Unknown"),
                ),
                "timestamp": idx.get("timestamp", meta.get("timestamp", "")),
                "severity_counts": idx.get(
                    "severity_counts",
                    {"critical": 0, "high": 0, "medium": 0, "low": 0},
                ),
                "risk_score": idx.get("risk_score", 0.0),
            }
        )

    for user_id, entries in per_user.items():
        entries.sort(key=lambda item: item.get("timestamp", ""))
        out_path = INDEX_DIR / f"{_safe_user_id(user_id)}.json"
        out_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        print(f"wrote {out_path.name}: {len(entries)} entries")

    print(f"done: {len(per_user)} user index files updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
