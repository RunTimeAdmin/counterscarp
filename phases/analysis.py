"""Analysis phases: SolanaPhase, UpgradeDiffPhase."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from scan_phase import ScanContext, ScanPhase


class SolanaPhase(ScanPhase):
    """Phase 6 — Solana/Anchor static analysis (optional, --solana-root + Pro license)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="solana", display_name="Solana Analyzer",
            requires_pro=True, **kwargs,
        )

    def should_run(self, ctx: ScanContext) -> bool:
        if not ctx.args.solana_root:
            return False
        from license_manager import LicenseManager, SOLANA
        _license = LicenseManager()
        if not (ctx.args.dev or _license.check_pro_feature(SOLANA)):
            ctx.logger.info(
                "Solana analysis requires Pro license: %s",
                _license.get_upgrade_message(SOLANA),
            )
            ctx.analyzer_status["Solana Analyzer"] = {
                "ran": False,
                "finding_count": 0,
                "error": "License required",
            }
            return False
        return True

    def run(self, ctx: ScanContext) -> Any:
        import types as _types

        solana_analyzer: Optional[_types.ModuleType] = None
        try:
            import solana_analyzer as _sa
            solana_analyzer = _sa
        except ImportError:
            pass

        solana_results: Optional[Dict] = None
        _solana_error: Optional[str] = None

        if solana_analyzer is None:
            ctx.logger.warning("solana_analyzer module not available")
            _solana_error = "solana_analyzer module not available"
        else:
            try:
                solana_results = solana_analyzer.analyze_solana_program(
                    ctx.args.solana_root
                )
                ctx.logger.info("Solana analysis complete")
            except Exception as e:
                ctx.logger.error("Solana analysis failed: %s", e)
                solana_results = {"error": "Solana analysis failed"}
                _solana_error = str(e)

        ctx.solana_results = solana_results
        _solana_count = (
            len((solana_results or {}).get("pattern_findings", []))
            if isinstance(solana_results, dict)
            and not (solana_results or {}).get("error")
            else 0
        )
        ctx.analyzer_status["Solana Analyzer"] = {
            "ran": solana_results is not None
            and not (isinstance(solana_results, dict) and solana_results.get("error")),
            "finding_count": _solana_count,
            "error": _solana_error,
        }
        return solana_results


class UpgradeDiffPhase(ScanPhase):
    """Phase 7 — Upgrade diff analysis (optional, --upgrade-old + --upgrade-new)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="upgrade_diff", display_name="Upgrade Diff", **kwargs)

    def should_run(self, ctx: ScanContext) -> bool:
        return bool(ctx.args.upgrade_old) and bool(ctx.args.upgrade_new)

    def run(self, ctx: ScanContext) -> Any:
        import types as _types

        upgrade_diff: Optional[_types.ModuleType] = None
        try:
            import upgrade_diff as _ud
            upgrade_diff = _ud
        except ImportError:
            pass

        upgrade_results: Optional[Dict] = None

        if upgrade_diff is None:
            ctx.logger.warning("upgrade_diff module not available")
        else:
            try:
                upgrade_results = upgrade_diff.analyze_upgrade(
                    ctx.args.upgrade_old, ctx.args.upgrade_new
                )
                ctx.logger.info("Upgrade diff analysis complete")
            except Exception as e:
                ctx.logger.error("Upgrade diff analysis failed: %s", e)
                upgrade_results = {"error": "Upgrade diff analysis failed"}

        ctx.upgrade_results = upgrade_results
        return upgrade_results
