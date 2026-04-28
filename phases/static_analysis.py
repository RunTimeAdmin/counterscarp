"""Static analysis phases: SupplyChain, Slither, Aderyn."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional, cast

from scan_phase import ScanContext, ScanPhase


class SupplyChainPhase(ScanPhase):
    """Phase 1 — Supply chain dependency check (package.json)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="supply_chain", display_name="Supply Chain", **kwargs)

    def run(self, ctx: ScanContext) -> List[Dict]:
        import supply_chain_check

        supply_issues: List[Dict] = []
        if os.path.isdir(ctx.target):
            pkg_json = os.path.join(ctx.target, "package.json")
            if os.path.exists(pkg_json):
                try:
                    supply_issues = supply_chain_check.scan_package_json(pkg_json)
                    ctx.logger.info(
                        "Supply chain scan complete: %d issues found", len(supply_issues)
                    )
                except Exception as e:
                    ctx.logger.warning(
                        "Supply chain check failed for %s: %s", pkg_json, e
                    )
                    supply_issues = []
            else:
                ctx.logger.info("No package.json found — skipping supply chain check")
        else:
            ctx.logger.info("Target is not a directory — skipping supply chain check")

        ctx.supply_issues = supply_issues
        ctx.analyzer_status["Supply Chain"] = {
            "ran": bool(supply_issues),
            "finding_count": len(supply_issues),
            "error": None,
        }
        return supply_issues


class SlitherPhase(ScanPhase):
    """Phase 2 — Slither static analysis."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="slither", display_name="Slither", **kwargs)

    def run(self, ctx: ScanContext) -> List[Dict]:
        import red_team_scan
        from exceptions import CounterscarpAnalysisError

        static_issues: List[Dict] = []
        _slither_error: Optional[str] = None
        try:
            raw_slither = red_team_scan.run_slither(
                ctx.target,
                stderr_log=ctx.stderr_log,
                exclude_paths=ctx.exclude_paths,
            )
            static_issues = red_team_scan.filter_vulnerabilities(raw_slither)
            ctx.logger.info(
                "Slither analysis complete: %d issues found", len(static_issues)
            )
        except CounterscarpAnalysisError as e:
            ctx.logger.error("Slither analysis failed: %s", e)
            static_issues = []
            _slither_error = str(e)
        except Exception as e:
            ctx.logger.error("Slither analysis unexpected failure: %s", e)
            static_issues = []
            _slither_error = str(e)

        ctx.static_issues = static_issues
        ctx.analyzer_status["Slither (Static Analysis)"] = {
            "ran": bool(static_issues),
            "finding_count": len(static_issues),
            "error": _slither_error,
        }
        return static_issues

    async def run_async(self, ctx: ScanContext) -> List[Dict]:
        """Async version — offloads blocking Slither subprocess to thread executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run, ctx)


class AderynPhase(ScanPhase):
    """Phase 2B — Aderyn static analysis (optional, --aderyn flag + directory target)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="aderyn", display_name="Aderyn", **kwargs)

    def should_run(self, ctx: ScanContext) -> bool:
        return bool(ctx.args.aderyn) and os.path.isdir(ctx.target)

    def run(self, ctx: ScanContext) -> Any:
        import types as _types

        aderyn_wrapper: Optional[_types.ModuleType] = None
        try:
            import aderyn_wrapper as _aw
            aderyn_wrapper = _aw
        except ImportError:
            pass

        aderyn_results: Optional[Dict] = None
        _aderyn_error: Optional[str] = None

        if aderyn_wrapper is None:
            ctx.logger.warning("Aderyn wrapper not available in this environment")
            _aderyn_error = "Aderyn wrapper not available"
        else:
            old_exit = sys.exit
            try:
                sys.exit = cast(Any, lambda code=0: None)
                aderyn_results = aderyn_wrapper.run_aderyn(
                    ctx.target, stderr_log=ctx.stderr_log
                )
                ctx.logger.info("Aderyn analysis complete")
            except Exception as e:
                ctx.logger.error(
                    "Aderyn analysis failed: %s — continuing without Aderyn results", e
                )
                aderyn_results = {"error": "Aderyn run failed"}
                _aderyn_error = str(e)
            finally:
                try:
                    sys.exit = old_exit
                except Exception:
                    pass

        ctx.aderyn_results = aderyn_results
        _aderyn_count = (
            len(aderyn_results.get("issues", []))
            if isinstance(aderyn_results, dict) and not aderyn_results.get("error")
            else 0
        )
        ctx.analyzer_status["Aderyn (Static Analysis)"] = {
            "ran": aderyn_results is not None
            and not (isinstance(aderyn_results, dict) and aderyn_results.get("error")),
            "finding_count": _aderyn_count,
            "error": _aderyn_error,
        }
        return aderyn_results

    async def run_async(self, ctx: ScanContext) -> Any:
        """Async version — offloads blocking Aderyn subprocess to thread executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run, ctx)
