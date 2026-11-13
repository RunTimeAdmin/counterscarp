"""Delete scan data on a schedule, so what the server keeps matches the
privacy page.

Uploads (the submitted source) are only needed while a scan runs. Results
hold findings and code snippets, kept for the dashboard for a limited time.
Runs hourly from the arq worker and once at web startup.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Optional

from logger import get_logger

logger = get_logger(__name__)

RESULT_RETENTION_DAYS = int(os.environ.get("RESULT_RETENTION_DAYS", "30"))
UPLOAD_RETENTION_HOURS = 24


def _owner(result_dir: Path) -> str:
    try:
        meta = json.loads((result_dir / "scan_meta.json").read_text(encoding="utf-8"))
        return str(meta.get("owner_user_id") or "")
    except (OSError, ValueError):
        return ""


def purge_expired(
    results_dir: Path,
    upload_dir: Path,
    result_days: int = RESULT_RETENTION_DAYS,
    now: Optional[float] = None,
) -> tuple[int, int]:
    """Remove expired result and upload folders. Returns (results, uploads) removed."""
    from webapp import audit_index

    now = time.time() if now is None else now
    removed_results = removed_uploads = 0

    if results_dir.is_dir():
        cutoff = now - result_days * 86400
        for entry in results_dir.iterdir():
            if entry.is_dir() and entry.stat().st_mtime < cutoff:
                owner = _owner(entry)
                shutil.rmtree(entry, ignore_errors=True)
                if owner:
                    try:
                        audit_index.remove(owner, entry.name)  # no dead dashboard links
                    except Exception as exc:  # index not configured or unreadable
                        logger.warning("Could not prune index for %s: %s", entry.name, exc)
                removed_results += 1

    if upload_dir.is_dir():
        cutoff = now - UPLOAD_RETENTION_HOURS * 3600
        for entry in upload_dir.iterdir():
            if entry.is_dir() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
                removed_uploads += 1

    if removed_results or removed_uploads:
        logger.info(
            "Retention: removed %d result folder(s) older than %d days and %d upload folder(s) older than %d hours",
            removed_results, result_days, removed_uploads, UPLOAD_RETENTION_HOURS,
        )
    return removed_results, removed_uploads
