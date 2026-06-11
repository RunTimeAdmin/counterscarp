"""Cross-process-safe per-user audit index.

Replaces the duplicate ``_update_user_audit_index`` implementations in
``webapp/main.py`` and ``webapp/worker.py``, which each used a
threading.Lock — useless across the separate web-server and arq-worker
processes.

On Linux (the VPS target) we use ``fcntl.flock`` advisory locking on a
stable sibling lock file so the web process and the arq worker serialise
correctly regardless of process boundaries. The data file itself is written
atomically via a temp-and-replace pattern to avoid partial reads.

On Windows (dev machines without fcntl) we fall back to a threading lock,
which is correct because the dev environment runs only one process.
"""

from __future__ import annotations

import json
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from logger import get_logger

logger = get_logger(__name__)

_INDEX_DIR: Path | None = None

# ---------------------------------------------------------------------------
# Platform locking
# ---------------------------------------------------------------------------

if sys.platform != "win32":
    import fcntl as _fcntl

    @contextmanager
    def _locked(path: Path) -> Iterator[None]:
        """Hold an exclusive flock on *path*.lock for the duration of the block."""
        lock_path = path.with_suffix(".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w", encoding="utf-8") as lock_file:
            _fcntl.flock(lock_file, _fcntl.LOCK_EX)
            try:
                yield
            finally:
                _fcntl.flock(lock_file, _fcntl.LOCK_UN)

else:
    import threading as _threading
    _windows_locks: dict[str, _threading.Lock] = {}
    _windows_meta_lock = _threading.Lock()

    @contextmanager
    def _locked(path: Path) -> Iterator[None]:
        key = str(path)
        with _windows_meta_lock:
            lock = _windows_locks.setdefault(key, _threading.Lock())
        with lock:
            yield


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def configure(index_dir: Path) -> None:
    """Set the directory where per-user index files are stored.

    Must be called once at application startup before any read/write.
    Both the web process (main.py startup) and the worker (WorkerSettings.on_startup)
    call this with the same path.
    """
    global _INDEX_DIR
    _INDEX_DIR = index_dir
    _INDEX_DIR.mkdir(parents=True, exist_ok=True)


def _require_dir() -> Path:
    if _INDEX_DIR is None:
        raise RuntimeError("audit_index.configure() must be called at startup")
    return _INDEX_DIR


def _index_path(user_id: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", user_id)[:128]
    return _require_dir() / f"{safe}.json"


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    tmp.replace(path)


def append(user_id: str, audit_summary: dict[str, Any]) -> None:
    """Append *audit_summary* to *user_id*'s index (cross-process safe)."""
    if not user_id:
        return
    path = _index_path(user_id)
    with _locked(path):
        entries = _read(path)
        entries.append(audit_summary)
        _write(path, entries)


def remove(user_id: str, audit_id: str) -> None:
    """Remove the entry for *audit_id* from *user_id*'s index."""
    if not user_id:
        return
    path = _index_path(user_id)
    with _locked(path):
        entries = [e for e in _read(path) if e.get("audit_id") != audit_id]
        _write(path, entries)


def replace(user_id: str, entries: list[dict[str, Any]]) -> None:
    """Overwrite *user_id*'s entire index with *entries* (for delete-then-persist)."""
    if not user_id:
        return
    path = _index_path(user_id)
    with _locked(path):
        _write(path, entries)


def list_audits(user_id: str) -> list[dict[str, Any]]:
    """Return all audit summaries for *user_id* (no locking — read-only snapshot)."""
    return _read(_index_path(user_id))
