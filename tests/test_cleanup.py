"""Tests for cleanup.py disk housekeeping."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_ENGINE_ROOT = str(Path(__file__).parent.parent)
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

import cleanup


@pytest.fixture
def artifact_tree(tmp_path: Path) -> Path:
    """Minimal project tree with stale and recent artifacts."""
    root = tmp_path
    old_ts = time.time() - (100 * 86400)
    recent_ts = time.time() - (1 * 86400)

    def _touch(path: Path, mtime: float) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * 100, encoding="utf-8")
        import os

        os.utime(path, (mtime, mtime))

    def _old_dir(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        _touch(path / "data.txt", old_ts)
        import os

        os.utime(path, (old_ts, old_ts))

    def _recent_dir(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        _touch(path / "data.txt", recent_ts)
        import os

        os.utime(path, (recent_ts, recent_ts))

    # Stale state file
    _touch(root / ".scarpshield" / "scan_state_old.json", old_ts)
    # Recent state file
    _touch(root / ".scarpshield" / "scan_state_new.json", recent_ts)
    _old_dir(root / "reports" / "old_scan")
    _recent_dir(root / "uploads" / "fresh")
    _old_dir(root / "results" / "dead-audit")

    return root


class TestCleanupStateFiles:
    def test_removes_old_state_only(self, artifact_tree: Path) -> None:
        stats = cleanup.cleanup_state_files(artifact_tree, max_age_days=30)
        assert stats.files_removed == 1
        assert (artifact_tree / ".scarpshield" / "scan_state_old.json").exists() is False
        assert (artifact_tree / ".scarpshield" / "scan_state_new.json").exists()

    def test_dry_run_keeps_files(self, artifact_tree: Path) -> None:
        cleanup.cleanup_state_files(artifact_tree, max_age_days=30, dry_run=True)
        assert (artifact_tree / ".scarpshield" / "scan_state_old.json").exists()


class TestCleanupDirectories:
    def test_removes_old_report_dirs(self, artifact_tree: Path) -> None:
        stats = cleanup.cleanup_old_directories(
            artifact_tree / "reports", max_age_days=30
        )
        assert stats.dirs_removed == 1
        assert not (artifact_tree / "reports" / "old_scan").exists()

    def test_keeps_recent_uploads(self, artifact_tree: Path) -> None:
        cleanup.cleanup_old_directories(artifact_tree / "uploads", max_age_days=7)
        assert (artifact_tree / "uploads" / "fresh").exists()


class TestRunCleanup:
    def test_run_cleanup_dry_run(self, artifact_tree: Path) -> None:
        stats = cleanup.run_cleanup(artifact_tree, dry_run=True, verbose=False)
        assert stats.bytes_freed > 0
        assert (artifact_tree / ".scarpshield" / "scan_state_old.json").exists()

    def test_run_cleanup_removes_stale(self, artifact_tree: Path) -> None:
        stats = cleanup.run_cleanup(artifact_tree, dry_run=False, verbose=False)
        assert stats.files_removed >= 1
        assert stats.dirs_removed >= 1
        assert not (artifact_tree / "reports" / "old_scan").exists()
        assert not (artifact_tree / "results" / "dead-audit").exists()

    def test_skip_results(self, artifact_tree: Path) -> None:
        cleanup.run_cleanup(
            artifact_tree, dry_run=False, verbose=False, include_results=False
        )
        assert (artifact_tree / "results" / "dead-audit").exists()


class TestDirSize:
    def test_empty_path(self, tmp_path: Path) -> None:
        assert cleanup.dir_size(tmp_path / "missing") == 0
