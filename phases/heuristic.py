"""Heuristic phases: HeuristicPhase, PluginPhase, FingerprintPhase, SymbolicPhase."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from scan_phase import ScanContext, ScanPhase


class HeuristicPhase(ScanPhase):
    """Phase 4 — Heuristic pattern scanner."""

    def __init__(self) -> None:
        super().__init__(name="heuristic", display_name="Heuristic Scanner")

    def run(self, ctx: ScanContext) -> List[Dict]:
        import heuristic_scanner

        heuristic_results: List[Dict] = []
        _heuristic_error: Optional[str] = None
        try:
            heuristic_findings = heuristic_scanner.scan_target(
                ctx.target, ctx.config, ctx.plugin_mgr, exclude_paths=ctx.exclude_paths
            )
            for hf in heuristic_findings:
                if not hf.suppressed:
                    heuristic_results.append(
                        {
                            "rule_id": hf.rule_id,
                            "severity": hf.severity,
                            "message": hf.message,
                            "file": hf.file,
                            "line_no": hf.line_no,
                            "line_text": hf.line_text,
                            "confidence": getattr(hf, "confidence", 5),
                        }
                    )
            ctx.logger.info(
                "Heuristic scan complete: %d findings (total), %d non-suppressed",
                len(heuristic_findings),
                len(heuristic_results),
            )
        except Exception as e:
            ctx.logger.error("Heuristic scan failed: %s", e)
            heuristic_results = []
            _heuristic_error = str(e)

        ctx.heuristic_results = heuristic_results
        ctx.analyzer_status["Heuristic Scanner"] = {
            "ran": bool(heuristic_results) or _heuristic_error is None,
            "finding_count": len(heuristic_results),
            "error": _heuristic_error,
        }
        return heuristic_results


class PluginPhase(ScanPhase):
    """Phase 4C — Plugin analyzer extensions (optional, requires plugin_mgr)."""

    def __init__(self) -> None:
        super().__init__(name="plugins", display_name="Plugin Analyzers")

    def should_run(self, ctx: ScanContext) -> bool:
        return ctx.plugin_mgr is not None and ctx.plugin_mgr.get_analyzer_count() > 0

    def run(self, ctx: ScanContext) -> List[Dict]:
        plugin_findings_acc: List[Dict] = []
        for plugin in ctx.plugin_mgr.get_analyzers():
            try:
                ctx.logger.info("Running plugin analyzer: %s", plugin.name)
                config_dict: Dict[str, Any] = (
                    {
                        "target": ctx.target,
                        "project_name": ctx.args.project_name,
                    }
                    if ctx.config
                    else {}
                )
                pf_list = plugin.analyze(ctx.target, config_dict)
                for pf in pf_list:
                    entry: Dict[str, Any] = {
                        "rule_id": pf.get("rule_id", f"PLUGIN-{plugin.name}"),
                        "severity": pf.get("severity", "Info"),
                        "message": pf.get("description", ""),
                        "file": pf.get("file", ""),
                        "line_no": pf.get("line_no", 0),
                        "line_text": pf.get("code_snippet", ""),
                    }
                    ctx.heuristic_results.append(entry)
                    plugin_findings_acc.append(entry)
            except Exception as exc:
                ctx.logger.warning("Plugin %s failed: %s", plugin.name, exc)
        return plugin_findings_acc


class FingerprintPhase(ScanPhase):
    """Phase 4B — Protocol fingerprint similarity scan (optional, --fingerprint flag + Pro)."""

    def __init__(self) -> None:
        super().__init__(name="fingerprint", display_name="Fingerprint Scan", requires_pro=True)

    def should_run(self, ctx: ScanContext) -> bool:
        if not ctx.args.fingerprint:
            return False
        from license_manager import LicenseManager, FINGERPRINT
        _license = LicenseManager()
        if not (ctx.args.dev or _license.check_pro_feature(FINGERPRINT)):
            ctx.logger.info(
                "Fingerprint scan requires Pro license: %s",
                _license.get_upgrade_message(FINGERPRINT),
            )
            return False
        return True

    def run(self, ctx: ScanContext) -> List[Dict]:
        try:
            import fingerprint_scanner
            from protocol_db import get_default_fingerprints, load_fingerprint_db
        except ImportError:
            ctx.logger.warning("Fingerprint scanner not available")
            return []

        fingerprint_results: List[Dict] = []
        try:
            min_similarity = 0.7
            database_path = None
            if ctx.config and hasattr(ctx.config, "fingerprint"):
                min_similarity = ctx.config.fingerprint.min_similarity
                database_path = ctx.config.fingerprint.database_path

            if database_path and os.path.exists(database_path):
                fingerprints = load_fingerprint_db(database_path)
            else:
                fingerprints = get_default_fingerprints()

            scan_config = {
                "fingerprints": fingerprints,
                "min_similarity": min_similarity,
            }
            fingerprint_results = fingerprint_scanner.scan_project(
                ctx.target,
                scan_config,
                exclude_paths=ctx.exclude_paths,
            )

            if fingerprint_results:
                total_fp_matches = sum(
                    len(r.get("matches", [])) for r in fingerprint_results
                )
                ctx.logger.info(
                    "Fingerprint scan complete: %d contracts with %d protocol matches",
                    len(fingerprint_results),
                    total_fp_matches,
                )
                for result in fingerprint_results:
                    matches = result.get("matches", [])
                    risk = result.get("risk_assessment", {})
                    ctx.logger.info("  - %s: %d match(es)", result["file"], len(matches))
                    if risk:
                        ctx.logger.info(
                            "    Risk Level: %s", risk.get("risk_level", "N/A")
                        )
            else:
                ctx.logger.info("No protocol matches found")

        except Exception as e:
            ctx.logger.error("Fingerprint scan failed: %s", e)

        ctx.fingerprint_results = fingerprint_results
        return fingerprint_results


class SymbolicPhase(ScanPhase):
    """Phase 5 — Mythril symbolic execution (optional, --symbolic flag + single .sol file)."""

    def __init__(self) -> None:
        super().__init__(name="mythril", display_name="Mythril (Symbolic)")

    def should_run(self, ctx: ScanContext) -> bool:
        return bool(ctx.args.symbolic) and os.path.isfile(ctx.target)

    def run(self, ctx: ScanContext) -> List[Dict]:
        import symbolic_wrapper

        symbolic_results: List[Dict] = []
        _mythril_error: Optional[str] = None
        try:
            raw_symbolic = symbolic_wrapper.run_mythril(
                ctx.target, stderr_log=ctx.stderr_log
            )
            symbolic_results = symbolic_wrapper.parse_issues(raw_symbolic)
            ctx.logger.info(
                "Symbolic analysis complete: %d issues found", len(symbolic_results)
            )
        except Exception as e:
            ctx.logger.error("Symbolic analysis failed: %s", e)
            symbolic_results = []
            _mythril_error = str(e)

        ctx.symbolic_results = symbolic_results
        ctx.analyzer_status["Mythril (Symbolic)"] = {
            "ran": bool(symbolic_results) or _mythril_error is None,
            "finding_count": len(symbolic_results),
            "error": _mythril_error,
        }
        return symbolic_results
