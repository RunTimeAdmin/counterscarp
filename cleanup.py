"""Counterscarp Engine — local disk cleanup for scan artifacts and caches."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("counterscarp.cleanup")

# Retention periods (days) — kept in sync with docs/CONFIGURATION.md and webapp startup.
DEFAULT_RETENTION_DAYS: Dict[str, int] = {
    "state": 30,
    "reports": 90,
    "uploads": 7,
    "results": 30,
    "sample_reports": 90,
    "history_reports": 90,
}

# Glob patterns for stale files directly under base_dir (not subdirectories).
ROOT_FILE_GLOBS = (
    "ACTION_PLAN_*.md",
    "audit_report_*.html",
    "audit_report_*.md",
    "scan_output.txt",
    "*.log",
)


@dataclass
class CleanupStats:
    """Summary of a cleanup run."""

    bytes_freed: int = 0
    files_removed: int = 0
    dirs_removed: int = 0
    skipped: List[str] = field(default_factory=list)

    def merge(self, other: "CleanupStats") -> None:
        self.bytes_freed += other.bytes_freed
        self.files_removed += other.files_removed
        self.dirs_removed += other.dirs_removed
        self.skipped.extend(other.skipped)


def dir_size(path: Path) -> int:
    """Return total byte size of *path* (file or directory tree)."""
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*"):
        if child.is_file():
            try:
                total += child.stat().st_size
            except OSError:
                pass
    return total


def _format_bytes(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


def _remove_path(path: Path, *, dry_run: bool) -> int:
    """Remove a file or directory tree; return bytes reclaimed (estimated)."""
    size = dir_size(path)
    if dry_run:
        return size
    try:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not remove %s: %s", path, exc)
        return 0
    return size


def cleanup_old_directories(
    base_dir: Path,
    max_age_days: int,
    *,
    dry_run: bool = False,
) -> CleanupStats:
    """Remove subdirectories of *base_dir* older than *max_age_days*."""
    stats = CleanupStats()
    if not base_dir.exists():
        return stats
    cutoff = time.time() - (max_age_days * 86400)
    for entry in base_dir.iterdir():
        if not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime >= cutoff:
                continue
        except OSError:
            stats.skipped.append(str(entry))
            continue
        stats.bytes_freed += _remove_path(entry, dry_run=dry_run)
        stats.dirs_removed += 1
    return stats


def cleanup_old_files_in_dir(
    base_dir: Path,
    max_age_days: int,
    patterns: tuple[str, ...],
    *,
    dry_run: bool = False,
) -> CleanupStats:
    """Remove files matching *patterns* directly under *base_dir*."""
    stats = CleanupStats()
    if not base_dir.exists():
        return stats
    cutoff = time.time() - (max_age_days * 86400)
    for pattern in patterns:
        for path in base_dir.glob(pattern):
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime >= cutoff:
                    continue
            except OSError:
                stats.skipped.append(str(path))
                continue
            stats.bytes_freed += _remove_path(path, dry_run=dry_run)
            stats.files_removed += 1
    return stats


def cleanup_state_files(
    base_dir: Path,
    max_age_days: int,
    *,
    dry_run: bool = False,
) -> CleanupStats:
    """Remove scan state and phase cache files older than *max_age_days*."""
    stats = CleanupStats()
    cutoff = time.time() - max_age_days * 86400
    patterns = ("scan_state_*.json", "phase_*_*.json")
    for state_dir in (base_dir / ".scarpshield", base_dir / ".counterscarp"):
        if not state_dir.exists():
            continue
        for pattern in patterns:
            for path in state_dir.glob(pattern):
                if not path.is_file():
                    continue
                try:
                    if path.stat().st_mtime >= cutoff:
                        continue
                except OSError:
                    stats.skipped.append(str(path))
                    continue
                stats.bytes_freed += _remove_path(path, dry_run=dry_run)
                stats.files_removed += 1
    return stats


def collect_usage(base_dir: Path) -> Dict[str, int]:
    """Return byte sizes for known artifact locations under *base_dir*."""
    locations = {
        "state (.scarpshield)": base_dir / ".scarpshield",
        "state (.counterscarp)": base_dir / ".counterscarp",
        "reports": base_dir / "reports",
        "uploads": base_dir / "uploads",
        "results": base_dir / "results",
        "sample_reports": base_dir / "sample_reports",
        "history_reports": base_dir / "history_reports",
        "exploits": base_dir / "exploits",
    }
    return {label: dir_size(path) for label, path in locations.items()}


def run_cleanup(
    base_dir: Optional[Path] = None,
    *,
    dry_run: bool = False,
    retention_days: Optional[Dict[str, int]] = None,
    include_results: bool = True,
    verbose: bool = True,
) -> CleanupStats:
    """Purge stale scan artifacts under *base_dir* (default: cwd).

    Args:
        base_dir: Project root containing reports/, uploads/, etc.
        dry_run: If True, only report what would be removed.
        retention_days: Override default per-category retention.
        include_results: When False, skip webapp ``results/`` cleanup.
        verbose: Print human-readable progress to stdout.

    Returns:
        Aggregate :class:`CleanupStats` for the run.
    """
    root = (base_dir or Path.cwd()).resolve()
    days = {**DEFAULT_RETENTION_DAYS, **(retention_days or {})}
    total = CleanupStats()

    if verbose:
        usage = collect_usage(root)
        print(f"Disk cleanup — project root: {root}")
        if dry_run:
            print("(dry run — nothing will be deleted)\n")
        print("Current artifact usage:")
        for label, size in usage.items():
            if size:
                print(f"  {label:<24} {_format_bytes(size)}")
        print()

    def _run(label: str, fn, *args, **kwargs) -> None:
        nonlocal total
        part = fn(*args, **kwargs)
        total.merge(part)
        if verbose and (part.files_removed or part.dirs_removed):
            action = "Would remove" if dry_run else "Removed"
            print(
                f"{action} {part.files_removed} file(s), "
                f"{part.dirs_removed} dir(s) from {label} "
                f"({_format_bytes(part.bytes_freed)})"
            )

    _run(
        "scan state",
        cleanup_state_files,
        root,
        days["state"],
        dry_run=dry_run,
    )
    _run(
        "reports/",
        cleanup_old_directories,
        root / "reports",
        days["reports"],
        dry_run=dry_run,
    )
    _run(
        "uploads/",
        cleanup_old_directories,
        root / "uploads",
        days["uploads"],
        dry_run=dry_run,
    )
    if include_results:
        _run(
            "results/",
            cleanup_old_directories,
            root / "results",
            days["results"],
            dry_run=dry_run,
        )
    _run(
        "sample_reports/",
        cleanup_old_directories,
        root / "sample_reports",
        days["sample_reports"],
        dry_run=dry_run,
    )
    _run(
        "history_reports/",
        cleanup_old_directories,
        root / "history_reports",
        days["history_reports"],
        dry_run=dry_run,
    )
    _run(
        "project root files",
        cleanup_old_files_in_dir,
        root,
        days["reports"],
        ROOT_FILE_GLOBS,
        dry_run=dry_run,
    )

    if verbose:
        action = "Would reclaim" if dry_run else "Freed"
        print(
            f"\n{action} approximately {_format_bytes(total.bytes_freed)} "
            f"({total.files_removed} files, {total.dirs_removed} directories)"
        )
        if total.skipped:
            print(f"Skipped {len(total.skipped)} path(s) due to permission errors.")

    return total


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for ``python -m cleanup`` or direct execution."""
    parser = argparse.ArgumentParser(
        description="Free local disk space by removing stale Counterscarp scan artifacts.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help="Project root (default: current working directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without removing anything",
    )
    parser.add_argument(
        "--skip-results",
        action="store_true",
        help="Do not clean webapp results/ directories",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress output (exit 0 on success)",
    )
    args = parser.parse_args(argv)
    run_cleanup(
        args.base_dir,
        dry_run=args.dry_run,
        include_results=not args.skip_results,
        verbose=not args.quiet,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
