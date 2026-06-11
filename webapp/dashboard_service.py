"""Dashboard audit-index loading helpers (refactored out of webapp/main.py).

BEFORE: webapp/main.py ``dashboard_page`` contained two ~40-line blocks that
were near-identical character-for-character — one for the per-user index file
and one for the legacy global index. Both parsed an entry dict, coerced the
timestamp, mapped lower->upper severity keys inline, and appended a display
dict. A third copy lived in ``_load_audits_from_results_dir``.

AFTER: a single ``audit_entry_to_view`` converts one stored entry into one
display row. ``load_audits_for_user`` owns the fast-path / legacy-path / slow-
path selection. ``dashboard_page`` shrinks from ~130 lines to ~25 and the
severity-key translation has exactly one implementation.

Behaviour is preserved: same keys, same defaults, same ordering, same
slow-path fallback warning and threadpool offload.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

# normalize_counts replaces the hand-written lower->upper mapping blocks.
from counterscarp_core.severity_scoring import normalize_counts

_TIMESTAMP_DISPLAY_FMT = "%b %d, %Y %H:%M"


def _coerce_timestamp(raw: Any) -> Optional[datetime]:
    """Parse an ISO timestamp string, returning None on any failure.

    Single implementation of the try/except that was inlined 3x.
    """
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except (ValueError, TypeError):
        return None


def audit_entry_to_view(
    entry: Dict[str, Any], *, has_report: bool = True
) -> Dict[str, Any]:
    """Convert one stored audit-index entry into a dashboard display row.

    Replaces the duplicated ``audits.append({...})`` blocks.
    Severity-count translation goes through ``normalize_counts``
    instead of four hand-typed ``.get(...)`` calls.
    """
    ts = _coerce_timestamp(entry.get("timestamp", ""))
    return {
        "audit_id": entry.get("audit_id", ""),
        "project_name": entry.get("project_name", "Unknown"),
        "timestamp": ts,
        "timestamp_display": (
            ts.strftime(_TIMESTAMP_DISPLAY_FMT) if ts else "N/A"
        ),
        "severity_counts": normalize_counts(
            entry.get("severity_counts", {}), to_upper=True
        ),
        "risk_score": entry.get("risk_score", 0.0),
        "has_report": has_report,
    }


def _read_json_list(path: Path) -> Optional[List[Dict[str, Any]]]:
    """Read a JSON array file, returning None if absent/corrupt."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, list) else None


async def load_audits_for_user(
    user_id: str,
    *,
    user_index_path: Path,
    legacy_global_index_path: Path,
    severity_weights: Dict[str, float],
    load_from_results_dir: Callable[
        [str, Dict[str, float]], List[Dict[str, Any]]
    ],
    run_in_threadpool: Callable[..., Awaitable[Any]],
    on_slow_path: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Load a user's audit history, preferring the fast per-user index.

    Selection order (unchanged from the original):
      1. Per-user index file (fast path).
      2. Legacy global index keyed by user_id (compat fallback).
      3. Walk RESULTS_DIR on disk (slow path, offloaded to a thread).

    Args mirror the collaborators the route already had access to; passing them
    in keeps this helper free of FastAPI/module-global coupling and
    unit-testable.
    """
    # --- Fast path: per-user index file ---
    entries = _read_json_list(user_index_path)
    if entries is not None:
        return [audit_entry_to_view(e) for e in entries]

    # --- Compat path: legacy global index keyed by user_id ---
    if legacy_global_index_path.exists():
        try:
            idx_data = json.loads(
                legacy_global_index_path.read_text(encoding="utf-8")
            )
            user_entries = idx_data.get(user_id, [])
        except (json.JSONDecodeError, OSError):
            user_entries = []
        if user_entries:
            return [audit_entry_to_view(e) for e in user_entries]

    # --- Slow path: scan results dir (blocking I/O → threadpool) ---
    if on_slow_path is not None:
        on_slow_path(user_id)
    return await run_in_threadpool(
        load_from_results_dir, str(user_id), severity_weights
    )


def paginate(
    items: List[Any], page_str: str, per_page: int
) -> Dict[str, Any]:
    """Clamp-and-slice pagination, extracted from the inline route logic."""
    try:
        page = max(1, int(page_str))
    except (ValueError, TypeError):
        page = 1
    total = len(items)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    return {
        "page_items": items[start:start + per_page],
        "page": page,
        "total_pages": total_pages,
        "total": total,
    }
