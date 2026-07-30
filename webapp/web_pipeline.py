"""Web-profile adapter: run the engine's PHASE_REGISTRY from the arq worker.

This replaces the bespoke scan sequence in ``webapp/worker.py`` with the same
pipeline the CLI uses, minus phases that require installed external tools with
long runtimes or are CLI-only (fuzzing, symbolic, history time-travel, and the
CLI-only report phase).

Usage::

    from webapp.web_pipeline import build_web_scan_context, WEB_PHASES, run_web_pipeline

    ctx = build_web_scan_context(
        target=str(upload_dir),
        output_dir=results_dir,
        license_tier=license_tier,
    )
    await run_web_pipeline(ctx)
    # ctx.heuristic_results, ctx.static_issues, ctx.fingerprint_results, etc. are populated
"""

from __future__ import annotations

import asyncio
import logging
import types
from pathlib import Path
from typing import Any

from logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Phases excluded from web scans
# ---------------------------------------------------------------------------
# Fuzzing and symbolic need CLI tools and can run for minutes.
# HistoryPhase needs a full git repo (not just uploaded files).
# ReportPhase is CLI-only (uses ctx.args.report flag).
_WEB_EXCLUDED = {
    "FoundryFuzzPhase",
    "MedusaFuzzPhase",
    "SymbolicPhase",
    "HistoryPhase",
    "ReportPhase",
}


def _build_web_phases() -> list:
    """Return PHASE_REGISTRY filtered to web-safe phases."""
    from phases import PHASE_REGISTRY
    return [p for p in PHASE_REGISTRY if type(p).__name__ not in _WEB_EXCLUDED]


WEB_PHASES = _build_web_phases()


class _WebArgs(types.SimpleNamespace):
    """Argparse-Namespace stand-in whose UNSET attributes default to None.

    A phase that gates on a flag we did not explicitly set then skips cleanly
    instead of raising AttributeError and crashing the whole pipeline — which
    is exactly what happened before (``fingerprint`` was missing, so every web
    scan threw and silently fell back to the legacy path).
    """

    def __getattr__(self, name: str) -> Any:  # invoked only on a lookup miss
        return None


def _make_minimal_args(output_dir: Path, **kwargs: Any) -> Any:
    """Build a minimal argparse-Namespace-like object for ScanContext."""
    ns = _WebArgs(
        target=None,          # set per-scan
        report=False,         # web worker handles report generation separately
        output=str(output_dir),
        fuzz_contract=None,
        symbolic=False,
        aderyn=False,
        medusa=False,
        history=False,
        resume=None,
        config=None,
        min_confidence=0,
        min_severity="INFO",
        fingerprint=True,     # protocol fingerprint (pro-gated in should_run)
        dev=False,
        rag=False,
        llm=False,
        project_name=None,
        solana_root=None,
        upgrade_old=None,
        upgrade_new=None,
        update_from_file=None,
        upgrade_old_str=None,
        upgrade_new_str=None,
    )
    # Allow callers to override any field
    for k, v in kwargs.items():
        setattr(ns, k, v)
    return ns


class _NullStateManager:
    """Minimal state manager for web scans — no caching or resume support."""

    def is_phase_pending(self, name: str) -> bool:
        return True

    def save_phase_results(self, name: str, results: Any) -> None:
        pass

    def mark_phase_complete(self, name: str, count: int, elapsed: float) -> None:
        logger.debug("Phase %s completed (%d findings, %.1fs)", name, count, elapsed)

    def load_phase_results(self, name: str) -> Any:
        return None


def build_web_scan_context(
    target: str,
    output_dir: Path,
    license_tier: str = "free",
    config: Any = None,
    exclude_paths: Any = None,
) -> Any:
    """Construct a ``ScanContext`` suitable for a web-profile scan.

    Args:
        target: Filesystem path to the uploaded file or directory.
        output_dir: Per-scan results directory.
        license_tier: ``"free"``, ``"pro"``, etc. — controls phase gating.
        config: Optional ``CounterscarpConfig``; defaults to default config.

    Returns:
        Populated ``ScanContext`` ready to pass to ``run_web_pipeline``.
    """
    from scan_phase import ScanContext

    if config is None:
        try:
            from config_loader import load_config
            config = load_config()
        except Exception:
            config = None

    stderr_log = str(output_dir / "stderr.log")
    args = _make_minimal_args(output_dir, target=target)

    return ScanContext(
        target=target,
        config=config,
        state_mgr=_NullStateManager(),
        logger=logger,
        license_tier=license_tier,
        args=args,
        scan_output_dir=output_dir,
        stderr_log=stderr_log,
        exclude_paths=exclude_paths or [],
        plugin_mgr=None,
    )


async def run_web_pipeline(ctx: Any) -> None:
    """Run the web-profile phases against *ctx*.

    Mirrors ``orchestrator.run_phases_async`` but uses ``WEB_PHASES`` and
    the ``_NullStateManager`` (no disk caching, no resume).
    """
    from orchestrator import run_phases_async
    await run_phases_async(ctx, WEB_PHASES)
