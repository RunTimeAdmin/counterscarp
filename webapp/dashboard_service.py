"""Dashboard service — single converter + loader for audit list views.

Collapses three near-identical parsing blocks from ``webapp/main.py``
(fast-path per-user index, legacy global index fallback, and
``_load_audits_from_results_dir``) into one ``audit_entry_to_view``
converter and one ``load_audits_for_user`` async loader.

Verified behaviour-preserving:
  - Keys from ``audit_entry_to_view`` are identical to the three old blocks.
  - ``timestamp`` falls back to ``None`` on any bad value → ``"N/A"`` display.
  - ``has_report`` defaults to ``True`` for index-sourced entries.
  - Pagination clamps ``page`` to ``[1, total_pages]``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Coroutine

from counterscarp_core.severity_scoring import normalize_counts


# ---------------------------------------------------------------------------
# Entry converter
# ---------------------------------------------------------------------------


def audit_entry_to_view(
    entry: dict[str, Any],
    *,
    has_report: bool = True,
) -> dict[str, Any]:
    """Convert a raw index dict to a template-ready display dict.

    Handles both lower-case keys (from scan_index.json / per-user index) and
    upper-case keys (from findings-based fallback).  Result always has
    UPPER-case severity keys — the dashboard template expects those.
    """
    ts: datetime | None = None
    ts_raw = entry.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw)
    except (ValueError, TypeError):
        pass

    return {
        "audit_id": entry.get("audit_id", ""),
        "project_name": entry.get("project_name", "Unknown"),
        "timestamp": ts,
        "timestamp_display": ts.strftime("%b %d, %Y %H:%M") if ts else "N/A",
        "severity_counts": normalize_counts(
            entry.get("severity_counts", {}), to_upper=True
        ),
        "risk_score": float(entry.get("risk_score", 0.0)),
        "has_report": has_report,
    }


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


async def load_audits_for_user(
    user_id: str,
    *,
    user_index_path: Path,
    legacy_global_index_path: Path,
    severity_weights: dict[str, float],
    load_from_results_dir: Callable[..., list[dict[str, Any]]],
    run_in_threadpool: Callable[..., Coroutine],
    on_slow_path: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Return a list of display-ready audit dicts for *user_id*.

    Resolution order (mirrors the previous inline logic):
    1. Per-user index file (fast path).
    2. Legacy global index (backward-compatible fallback).
    3. Full results-dir walk (slow path — triggers ``on_slow_path`` callback).
    """
    import json

    audits: list[dict[str, Any]] = []
    used_index = False

    # 1. Fast path: per-user index
    if user_index_path.exists():
        try:
            raw = json.loads(user_index_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                audits = [audit_entry_to_view(e) for e in raw]
                used_index = True
        except (json.JSONDecodeError, OSError):
            pass

    # 2. Legacy global index
    if not used_index and legacy_global_index_path.exists():
        try:
            idx_data = json.loads(
                legacy_global_index_path.read_text(encoding="utf-8")
            )
            user_entries = idx_data.get(user_id, [])
            if user_entries:
                audits = [audit_entry_to_view(e) for e in user_entries]
                used_index = True
        except (json.JSONDecodeError, OSError):
            pass

    # 3. Slow path: walk results dir
    if not used_index:
        if on_slow_path is not None:
            on_slow_path(user_id)
        audits = await run_in_threadpool(
            load_from_results_dir, user_id, severity_weights
        )

    return audits


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def paginate(
    items: list[Any],
    page_str: str | int,
    *,
    per_page: int = 20,
) -> dict[str, Any]:
    """Return a pagination result dict.

    ``page`` is clamped to ``[1, total_pages]``.  Works with any list.
    """
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
