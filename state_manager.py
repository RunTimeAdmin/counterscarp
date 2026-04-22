#!/usr/bin/env python3
"""
Counterscarp Engine — Scan state persistence for resume capability.

Provides the ScanStateManager class for writing and reading scan state
files that enable the --resume flag to restart a scan from the last
completed analysis phase.
"""

import dataclasses
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set, cast

from exceptions import CounterscarpError

logger = logging.getLogger("counterscarp.state_manager")


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class StateError(CounterscarpError):
    """Raised for state persistence or session management errors.

    Example:
        >>> raise StateError("State file not found", details={"path": "..."})
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details)


# ---------------------------------------------------------------------------
# JSON encoder
# ---------------------------------------------------------------------------

class _CounterscarpJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles dataclasses, datetime, and Path."""

    def default(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


# ---------------------------------------------------------------------------
# ScanStateManager
# ---------------------------------------------------------------------------

class ScanStateManager:
    """Manages per-session scan state files for resume capability.

    State files are stored as JSON inside *counterscarp_dir* (default
    ``.counterscarp/``).  Each session produces:

    * ``scan_state_{session_id}.json``  — top-level session record
    * ``phase_{phase_name}_{session_id}.json``  — per-phase result blobs

    Args:
        counterscarp_dir: Directory path where state files are stored.
            Created automatically if it does not exist.
    """

    def __init__(self, counterscarp_dir: str = ".counterscarp") -> None:
        self._dir = Path(counterscarp_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._session_id: Optional[str] = None
        self._state_file: Optional[Path] = None
        logger.debug("ScanStateManager initialised with dir=%s", self._dir)

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start_session(self, target: str, cli_args: Dict[str, Any]) -> str:
        """Create a new scan session and return its session ID.

        Args:
            target: Path or identifier of the contract/directory being scanned.
            cli_args: Dictionary of CLI flags/options passed to the scan.

        Returns:
            The generated session_id string.
        """
        session_id = (
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        )
        self._session_id = session_id
        self._state_file = self._dir / f"scan_state_{session_id}.json"

        state: Dict[str, Any] = {
            "session_id": session_id,
            "target": target,
            "cli_args": cli_args,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phases_completed": [],
            "status": "in_progress",
        }
        self._write_json(self._state_file, state)
        logger.info("Session started: %s (target=%s)", session_id, target)
        return session_id

    def mark_session_complete(self) -> None:
        """Mark the active session as completed.

        Raises:
            StateError: If no session is currently active.
        """
        state = self._load_active_state()
        state["status"] = "completed"
        state["completed_at"] = datetime.now(timezone.utc).isoformat()
        self._write_json(self._state_file, state)  # type: ignore[arg-type]
        logger.info("Session completed: %s", self._session_id)

    # ------------------------------------------------------------------
    # Phase tracking
    # ------------------------------------------------------------------

    def mark_phase_complete(
        self,
        phase_name: str,
        findings_count: int = 0,
        duration_secs: float = 0.0,
    ) -> None:
        """Record a phase as completed in the active session state.

        Args:
            phase_name: Identifier for the analysis phase (e.g. ``"slither"``).
            findings_count: Number of findings produced by this phase.
            duration_secs: Wall-clock seconds the phase took.

        Raises:
            StateError: If no active session exists.
        """
        state = self._load_active_state()
        entry: Dict[str, Any] = {
            "name": phase_name,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": findings_count,
            "duration_secs": round(duration_secs, 3),
        }
        state["phases_completed"].append(entry)
        self._write_json(self._state_file, state)  # type: ignore[arg-type]
        logger.debug(
            "Phase complete: %s | findings=%d | duration=%.2fs",
            phase_name,
            findings_count,
            duration_secs,
        )

    def get_completed_phases(self) -> Set[str]:
        """Return the set of completed phase names for the active session.

        Returns:
            Set of phase name strings.

        Raises:
            StateError: If no active session exists.
        """
        state = self._load_active_state()
        return {entry["name"] for entry in state.get("phases_completed", [])}

    def is_phase_pending(self, phase_name: str) -> bool:
        """Check whether a phase has NOT yet been completed.

        Args:
            phase_name: Phase identifier to check.

        Returns:
            ``True`` if the phase has not been marked complete.
        """
        return phase_name not in self.get_completed_phases()

    # ------------------------------------------------------------------
    # Phase result blobs
    # ------------------------------------------------------------------

    def save_phase_results(self, phase_name: str, data: Any) -> None:
        """Persist arbitrary phase result data to disk.

        Args:
            phase_name: Phase identifier used in the filename.
            data: Serialisable object (dict, list, dataclass, etc.).

        Raises:
            StateError: If no active session exists.
        """
        if self._session_id is None:
            raise StateError(
                "No active session — call start_session() first.",
                details={"phase": phase_name},
            )
        result_file = self._dir / f"phase_{phase_name}_{self._session_id}.json"
        self._write_json(result_file, data)
        logger.debug("Phase results saved: %s", result_file.name)

    def load_phase_results(self, phase_name: str) -> Any:
        """Load previously saved phase result data.

        Args:
            phase_name: Phase identifier to load.

        Returns:
            Deserialised data, or ``None`` if no results file exists.

        Raises:
            StateError: If no active session exists.
        """
        if self._session_id is None:
            raise StateError(
                "No active session — call start_session() or load_session() first.",
                details={"phase": phase_name},
            )
        result_file = self._dir / f"phase_{phase_name}_{self._session_id}.json"
        if not result_file.exists():
            logger.debug("No phase results file found: %s", result_file.name)
            return None
        with result_file.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    # ------------------------------------------------------------------
    # Session loading
    # ------------------------------------------------------------------

    def load_session(self, session_id: str) -> Dict[str, Any]:
        """Load an existing session by ID and make it the active session.

        Args:
            session_id: The session ID to load.

        Returns:
            The full session state dictionary.

        Raises:
            FileNotFoundError: If no state file exists for this session_id.
            StateError: If the state file cannot be parsed.
        """
        state_file = self._dir / f"scan_state_{session_id}.json"
        if not state_file.exists():
            raise FileNotFoundError(
                f"No state file found for session '{session_id}': {state_file}"
            )
        try:
            with state_file.open("r", encoding="utf-8") as fh:
                state: Dict[str, Any] = json.load(fh)
        except json.JSONDecodeError as exc:
            raise StateError(
                f"State file for session '{session_id}' is corrupt.",
                details={"path": str(state_file)},
            ) from exc

        # Make this the active session so subsequent calls work
        self._session_id = session_id
        self._state_file = state_file
        logger.info("Session loaded: %s", session_id)
        return state

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_old_sessions(self, max_age_days: int = 30) -> None:
        """Remove state and phase result files older than *max_age_days*.

        Args:
            max_age_days: Files older than this many days are deleted.
        """
        cutoff = time.time() - max_age_days * 86400
        patterns = ["scan_state_*.json", "phase_*_*.json"]
        removed = 0
        for pattern in patterns:
            for path in self._dir.glob(pattern):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        removed += 1
                        logger.debug("Removed old state file: %s", path.name)
                except OSError as exc:
                    logger.warning(
                        "Could not remove %s: %s", path.name, exc
                    )
        logger.info(
            "Cleanup complete: removed %d file(s) older than %d day(s).",
            removed,
            max_age_days,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_active_state(self) -> Dict[str, Any]:
        """Load the current active state file.

        Returns:
            Parsed state dictionary.

        Raises:
            StateError: If no session is active or the file cannot be read.
        """
        if self._session_id is None or self._state_file is None:
            raise StateError(
                "No active session — call start_session() or load_session() first."
            )
        if not self._state_file.exists():
            raise StateError(
                f"State file missing for session '{self._session_id}'.",
                details={"path": str(self._state_file)},
            )
        try:
            with self._state_file.open("r", encoding="utf-8") as fh:
                return cast(Dict[str, Any], json.load(fh))
        except json.JSONDecodeError as exc:
            raise StateError(
                f"State file is corrupt for session '{self._session_id}'.",
                details={"path": str(self._state_file)},
            ) from exc

    def _write_json(self, path: Path, data: Any) -> None:
        """Atomically write *data* as JSON to *path*.

        Uses a temporary sibling file + rename for crash safety.

        Args:
            path: Destination file path.
            data: JSON-serialisable object.
        """
        tmp_path = path.with_suffix(".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, cls=_CounterscarpJSONEncoder)
                fh.write("\n")
            tmp_path.replace(path)
        except OSError as exc:
            raise StateError(
                f"Failed to write state file: {path}",
                details={"path": str(path)},
            ) from exc


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    sm = ScanStateManager()
    sid = sm.start_session("/tmp/test", {"report": True})
    sm.mark_phase_complete("slither", 5, 12.3)
    print(sm.get_completed_phases())
    print("OK")
