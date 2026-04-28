"""Enrichment phases: RagEnrichPhase, ExploitGenPhase, HistoryPhase."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from scan_phase import ScanContext, ScanPhase


class RagEnrichPhase(ScanPhase):
    """Phase 7.5 — RAG/LLM enrichment of findings (optional, --rag + Pro)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="rag_enrichment", display_name="RAG Enrichment",
            requires_pro=True, **kwargs,
        )

    def should_run(self, ctx: ScanContext) -> bool:
        if not ctx.args.rag:
            return False
        try:
            from rag_engine import AuditCopilot  # noqa: F401
            rag_available = True
        except ImportError:
            rag_available = False
        if not rag_available:
            ctx.logger.warning(
                "RAG engine not available — cannot enrich findings. "
                "Install: pip install sentence-transformers numpy"
            )
            return False
        from license_manager import LicenseManager, AI_COPILOT
        _license = LicenseManager()
        if not (ctx.args.dev or _license.check_pro_feature(AI_COPILOT)):
            ctx.logger.info(
                "RAG enrichment requires Pro license: %s",
                _license.get_upgrade_message(AI_COPILOT),
            )
            return False
        return True

    def run(self, ctx: ScanContext) -> Any:
        from rag_engine import AuditCopilot

        try:
            rag_config: Dict[str, Any] = {}
            if ctx.config and hasattr(ctx.config, "ai"):
                rag_config = {
                    "embedding_backend": ctx.config.ai.embedding_backend,
                    "rag_index_path": ctx.config.ai.rag_index_path,
                    "top_k": ctx.config.ai.top_k,
                    "llm_enrichment": (
                        ctx.args.llm or getattr(ctx.config.ai, "llm_enrichment", False)
                    ),
                }
            elif ctx.args.llm:
                rag_config = {"llm_enrichment": True}

            copilot = AuditCopilot(rag_config)

            if copilot.vector_store.entries:
                rag_offline = False
                if ctx.heuristic_results and not rag_offline:
                    ctx.heuristic_results = copilot.enrich_findings_batch(
                        ctx.heuristic_results
                    )
                    ctx.logger.info(
                        "Enriched %d heuristic findings", len(ctx.heuristic_results)
                    )
                    if any(
                        r.get("rag_status") == "offline" for r in ctx.heuristic_results
                    ):
                        ctx.logger.warning(
                            "AI Copilot offline — continuing scan without LLM enrichment"
                        )
                        rag_offline = True

                if ctx.static_issues and not rag_offline:
                    ctx.static_issues = copilot.enrich_findings_batch(ctx.static_issues)
                    ctx.logger.info(
                        "Enriched %d static analysis findings", len(ctx.static_issues)
                    )
                    if any(
                        r.get("rag_status") == "offline" for r in ctx.static_issues
                    ):
                        ctx.logger.warning(
                            "AI Copilot offline — continuing scan without LLM enrichment"
                        )
                        rag_offline = True

                if not rag_offline:
                    ctx.logger.info("RAG enrichment complete")
                else:
                    ctx.logger.warning(
                        "RAG enrichment aborted — offline mode (AI Copilot offline)"
                    )
            else:
                ctx.logger.warning(
                    "No RAG index found — cannot enrich findings. Build with: --build-rag-index"
                )

        except Exception as e:
            ctx.logger.warning("RAG enrichment failed: %s", e)

        # Return the enriched blobs (saved to state so resume works)
        return {"heuristic": ctx.heuristic_results, "static": ctx.static_issues}

    def load_cached(self, ctx: ScanContext, data: Any) -> None:
        """Restore enriched results from cache on resume."""
        if isinstance(data, dict):
            if data.get("heuristic") is not None:
                ctx.heuristic_results = data["heuristic"]
            if data.get("static") is not None:
                ctx.static_issues = data["static"]
        ctx.logger.info("[PHASE 7.5] RAG Enrichment — loaded from cache (resumed)")

    async def run_async(self, ctx: ScanContext) -> Any:
        """Async version — offloads RAG/LLM enrichment (blocking I/O) to thread executor.

        Falls back to asyncio.to_thread if httpx.AsyncClient is unavailable.
        The RAG engine currently uses synchronous embedding/inference, so we
        run it in a thread pool to avoid blocking the event loop.
        """
        return await asyncio.get_running_loop().run_in_executor(None, self.run, ctx)


class ExploitGenPhase(ScanPhase):
    """Phase 8 — Exploit PoC generation for CRITICAL/HIGH findings (Pro)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="exploit_gen", display_name="Exploit Generator", **kwargs)

    def run(self, ctx: ScanContext) -> Any:
        exploit_results: Optional[List] = None
        try:
            from exploit_generator import ExploitGenerator
            from license_manager import LicenseManager, EXPLOIT_GEN

            _license = LicenseManager()
            if ctx.args.dev or _license.check_pro_feature(EXPLOIT_GEN):
                _default_exploit_dir = str(ctx.scan_output_dir / "exploits")
                exploit_config: Dict[str, Any] = {}
                if ctx.config is not None and hasattr(ctx.config, "exploit_generation"):
                    eg = ctx.config.exploit_generation
                    exploit_config = {
                        "min_severity": getattr(eg, "min_severity", "HIGH"),
                        "validate_compilation": getattr(
                            eg, "validate_compilation", True
                        ),
                        "output_dir": _default_exploit_dir,
                        "llm_backend": getattr(eg, "llm_backend", "none"),
                        "template_dir": getattr(
                            eg, "template_dir", "exploit_templates/"
                        ),
                    }
                else:
                    exploit_config["output_dir"] = _default_exploit_dir

                generator = ExploitGenerator(
                    config=exploit_config,
                    template_dir=exploit_config.get("template_dir", "exploit_templates/"),
                    output_dir=exploit_config.get("output_dir", _default_exploit_dir),
                    llm_backend=exploit_config.get("llm_backend", "none"),
                )

                critical_findings: List[Dict[str, Any]] = []
                for h in ctx.heuristic_results:
                    sev = h.get("severity", "").upper()
                    if sev in ("CRITICAL", "HIGH"):
                        critical_findings.append(h)
                for s in ctx.static_issues:
                    impact = s.get("impact", "").lower()
                    if impact in ("high", "critical"):
                        critical_findings.append(
                            {
                                "rule_id": s.get("check", s.get("title", "unknown")),
                                "severity": impact.upper(),
                                "description": s.get("description", ""),
                                "file": s.get("location", ""),
                                "line_no": 0,
                                "message": s.get("description", ""),
                            }
                        )

                if critical_findings:
                    ctx.logger.info(
                        "Generating exploit PoCs for %d critical/high findings...",
                        len(critical_findings),
                    )
                    exploit_results = generator.batch_generate(
                        critical_findings,
                        output_dir=exploit_config.get(
                            "output_dir", _default_exploit_dir
                        ),
                    )
                    successful = [r for r in exploit_results if r.status == "success"]
                    ctx.logger.info(
                        "Generated %d exploit PoCs out of %d findings",
                        len(successful),
                        len(critical_findings),
                    )
                else:
                    exploit_results = []
                    ctx.logger.info(
                        "No CRITICAL/HIGH findings for exploit generation"
                    )
            else:
                from license_manager import LicenseManager, EXPLOIT_GEN
                _license2 = LicenseManager()
                ctx.logger.info(
                    "Exploit PoC generation requires Pro tier license: %s",
                    _license2.get_upgrade_message(EXPLOIT_GEN),
                )

        except ImportError:
            ctx.logger.warning("Exploit generator module not available")
        except Exception as _eg_exc:
            ctx.logger.warning("Exploit generation failed: %s", _eg_exc)

        ctx.exploit_results = exploit_results

        # Return serializable metadata for state_mgr
        _exploit_meta = [
            {
                "finding": getattr(r, "finding", {}),
                "status": getattr(r, "status", ""),
                "output_path": getattr(r, "output_path", ""),
            }
            for r in (exploit_results or [])
        ]
        return _exploit_meta


class HistoryPhase(ScanPhase):
    """Phase 8B — Inline Time-Travel historical scan (Pro, when --report + git repo)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="time_travel", display_name="Time-Travel Scan",
            requires_pro=True, **kwargs,
        )

    def should_run(self, ctx: ScanContext) -> bool:
        if not ctx.args.report:
            return False
        try:
            import history_scanner  # noqa: F401
        except ImportError:
            return False
        from license_manager import LicenseManager, TIME_TRAVEL
        _license = LicenseManager()
        if not (ctx.args.dev or _license.check_pro_feature(TIME_TRAVEL)):
            return False
        if not os.path.isdir(ctx.target):
            return False
        if not os.path.isdir(os.path.join(ctx.target, ".git")):
            return False
        try:
            from report_generator import aggregate_findings_from_orchestrator  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, ctx: ScanContext) -> List[Dict]:
        import history_scanner

        history_timeline: List[Dict] = []
        try:
            _hist_output_dir = "."
            if ctx.config and hasattr(ctx.config, "history") and ctx.config.history:
                _hist_output_dir = getattr(ctx.config.history, "output_dir", ".")

            _hist_results = history_scanner.scan_history(
                repo_path=ctx.target,
                max_commits=getattr(ctx.args, "commits", 50),
                since=getattr(ctx.args, "since", None),
                branch=getattr(ctx.args, "branch", "main"),
                output_dir=_hist_output_dir,
                config=ctx.config,
                stderr_log=ctx.stderr_log,
            )
            _hist_json_path = (_hist_results.get("reports") or {}).get("json", "")
            if _hist_json_path and os.path.isfile(_hist_json_path):
                with open(_hist_json_path, "r", encoding="utf-8") as _f:
                    _hist_data = json.load(_f)
                history_timeline = _hist_data.get("timeline", [])
            ctx.logger.info(
                "Time-Travel scan complete: %d timeline entries", len(history_timeline)
            )
            ctx.logger.info(
                "Time-Travel scan complete: %d historical vulnerabilities",
                _hist_results.get("total_vulnerabilities", 0),
            )
        except Exception as _hist_exc:
            ctx.logger.warning("Inline Time-Travel scan failed: %s", _hist_exc)

        ctx.history_timeline = history_timeline
        return history_timeline
