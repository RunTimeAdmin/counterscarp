"""Phase-based scan architecture for Counterscarp Engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """Shared context passed to all scan phases."""
    # Core scan targets
    target: str                        # path string (args.target)
    config: Any                        # CounterscarpConfig | None
    state_mgr: Any                     # ScanStateManager instance
    logger: logging.Logger
    license_tier: str                  # "free" | "pro" | "enterprise"

    # CLI args (full namespace, to avoid threading each field individually)
    args: Any                          # argparse.Namespace

    # Computed at setup time
    scan_output_dir: Path              # per-scan output directory
    stderr_log: str                    # path for stderr capture
    exclude_paths: List[str]           # list of glob exclusion patterns
    plugin_mgr: Any                    # PluginManager | None

    # Accumulated results (phases append here as they complete)
    supply_issues: List[Dict] = field(default_factory=list)
    static_issues: List[Dict] = field(default_factory=list)
    fuzz_issues: List[Dict] = field(default_factory=list)
    heuristic_results: List[Dict] = field(default_factory=list)
    symbolic_results: List[Dict] = field(default_factory=list)
    aderyn_results: Optional[Dict] = None
    medusa_results: Optional[Dict] = None
    solana_results: Optional[Dict] = None
    upgrade_results: Optional[Dict] = None
    fingerprint_results: List[Dict] = field(default_factory=list)
    exploit_results: Optional[List] = None
    history_timeline: List[Dict] = field(default_factory=list)

    # Analyzer status tracking (for report coverage table)
    analyzer_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class ScanPhase:
    """Base class for a scan phase."""
    name: str           # Must match existing state_mgr phase names exactly
    display_name: str
    requires_pro: bool = False
    requires_tool: Optional[str] = None

    def should_run(self, ctx: ScanContext) -> bool:
        """Check if this phase should run given the context.

        Override in subclasses for custom conditional logic.
        """
        if self.requires_pro and ctx.license_tier == "free":
            return False
        return True

    def run(self, ctx: ScanContext) -> Any:
        """Execute the phase.

        Override in subclasses.  Most phases return a list[dict] of findings;
        the ReportPhase is special and returns None (side-effects only).
        """
        raise NotImplementedError(f"Phase {self.name} must implement run()")

    async def run_async(self, ctx: ScanContext) -> Any:
        """Async version of run(). Override in subclasses that use subprocess/network I/O.

        Default implementation runs the sync version in a thread executor
        to avoid blocking the event loop.
        """
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run, ctx)
