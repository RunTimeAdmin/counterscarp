"""Reporting phase: ReportPhase (Phase 9)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from scan_phase import ScanContext, ScanPhase


def _safe_line_no(location_str: str) -> int:
    """Extract line number from location string, handling various formats."""
    if not location_str or ":" not in location_str:
        return 0
    try:
        part = location_str.split(":")[-1].strip()
        if part.startswith("[") or part.startswith(" ["):
            import re
            nums = re.findall(r"\d+", part)
            return int(nums[0]) if nums else 0
        return int(part)
    except (ValueError, IndexError):
        return 0


class ReportPhase(ScanPhase):
    """Phase 9 — Professional audit report generation (optional, --report flag)."""

    def __init__(self) -> None:
        super().__init__(name="report", display_name="Professional Report")

    def should_run(self, ctx: ScanContext) -> bool:
        if not ctx.args.report:
            return False
        try:
            from report_generator import create_audit_report  # noqa: F401
            return True
        except ImportError:
            ctx.logger.error(
                "Report generation requested but report_generator.py not available"
            )
            return False

    def run(self, ctx: ScanContext) -> None:
        """Generate professional audit reports (HTML, Markdown, PDF).

        Returns None — this phase produces output files, not findings.
        """
        try:
            from report_generator import (
                Finding,
                create_audit_report,
                generate_html_report,
                generate_markdown_report,
                generate_pdf_report,
            )
        except ImportError as e:
            ctx.logger.error("Report generator import failed: %s", e)
            return None

        try:
            from importlib.metadata import version as _pkg_version
            _ENGINE_VERSION = _pkg_version("counterscarp-engine")
        except Exception:
            _ENGINE_VERSION = "5.0.0"

        ctx.logger.info("[PHASE 9] Generating Professional Audit Report")

        all_findings: List[Any] = []

        # Heuristics
        for h in ctx.heuristic_results:
            all_findings.append(
                Finding(
                    rule_id=h["rule_id"],
                    severity=h["severity"],
                    category="Heuristic",
                    title=h["rule_id"].replace("_", " ").title(),
                    description=h["message"],
                    file=h["file"],
                    line_no=h["line_no"],
                    code_snippet=h.get("line_text", ""),
                    rag_similar_findings=h.get("rag_similar_findings", []),
                    rag_remediation=h.get("rag_remediation", ""),
                    rag_references=h.get("rag_references", []),
                )
            )

        # Static (Slither)
        for s in ctx.static_issues:
            all_findings.append(
                Finding(
                    rule_id=s.get("check", "slither_finding"),
                    severity=s.get("impact", "MEDIUM").upper(),
                    category="Slither",
                    title=s.get("title", "Slither Finding"),
                    description=s.get("description", ""),
                    file=(
                        s.get("location", "").split(":")[0]
                        if ":" in s.get("location", "")
                        else s.get("location", "")
                    ),
                    line_no=_safe_line_no(s.get("location", "")),
                    rag_similar_findings=s.get("rag_similar_findings", []),
                    rag_remediation=s.get("rag_remediation", ""),
                    rag_references=s.get("rag_references", []),
                )
            )

        # Aderyn
        if ctx.aderyn_results and isinstance(ctx.aderyn_results, dict):
            for issue in ctx.aderyn_results.get("high", [])[:10]:
                all_findings.append(
                    Finding(
                        rule_id=issue.get("detector_name", "aderyn_finding"),
                        severity="HIGH",
                        category="Aderyn",
                        title=issue.get("title", "Aderyn Finding"),
                        description=issue.get("description", ""),
                        file="",
                        line_no=0,
                    )
                )

        # Upgrade Diff
        if ctx.upgrade_results and isinstance(ctx.upgrade_results, dict):
            for issue in ctx.upgrade_results.get("issues", []):
                all_findings.append(
                    Finding(
                        rule_id=(
                            issue.category if hasattr(issue, "category") else "upgrade_issue"
                        ),
                        severity=(
                            issue.severity if hasattr(issue, "severity") else "HIGH"
                        ),
                        category="Upgrade Diff",
                        title=(
                            issue.title if hasattr(issue, "title") else "Upgrade Issue"
                        ),
                        description=(
                            issue.description if hasattr(issue, "description") else ""
                        ),
                        file="",
                        line_no=(
                            issue.line_no
                            if hasattr(issue, "line_no") and issue.line_no
                            else 0
                        ),
                    )
                )

        # Solana
        if ctx.solana_results and isinstance(ctx.solana_results, dict):
            for f in ctx.solana_results.get("pattern_findings", []):
                if hasattr(f, "severity"):
                    all_findings.append(
                        Finding(
                            rule_id=f.category,
                            severity=f.severity,
                            category="Solana",
                            title=f.title,
                            description=f.description,
                            file=f.file,
                            line_no=f.line_no,
                            remediation=(
                                f.fix_suggestion if hasattr(f, "fix_suggestion") else ""
                            ),
                        )
                    )

        # Historical / Time-Travel
        for _ht in ctx.history_timeline:
            _status = _ht.get("status", "active")
            if _status != "active":
                continue

            _raw_rule = _ht.get("rule_id", "UNKNOWN")
            _severity = (_ht.get("severity") or "INFO").upper()
            _file = _ht.get("file", "")
            _line_no = int(_ht.get("line_no", 0) or 0)
            _intro_commit = (_ht.get("introduced_commit") or "")[:8]
            _intro_date = (_ht.get("introduced_date") or "")[:10]
            _intro_author = _ht.get("introduced_author") or "unknown"
            _lifespan = int(_ht.get("lifespan_days", 0) or 0)

            _title = (
                f"[Historical] {_raw_rule.replace('_', ' ').title()} "
                f"(introduced {_intro_date})"
            )
            _description_parts = [
                "This vulnerability was detected by Time-Travel historical scan.",
                f"Introduced in commit {_intro_commit} on {_intro_date} by {_intro_author}.",
            ]
            if _lifespan > 0:
                _description_parts.append(
                    f"Has persisted for at least {_lifespan} days without being fixed."
                )

            all_findings.append(
                Finding(
                    rule_id=f"HIST-{_raw_rule}",
                    severity=_severity,
                    category="Historical Analysis",
                    title=_title,
                    description=" ".join(_description_parts),
                    file=_file,
                    line_no=_line_no,
                )
            )

        if ctx.history_timeline:
            _active_hist = sum(
                1 for _ht in ctx.history_timeline if _ht.get("status") == "active"
            )
            ctx.logger.info(
                "Added %d active historical findings to unified report "
                "(%d total in timeline)",
                _active_hist,
                len(ctx.history_timeline),
            )

        # Wire exploit PoC results into unified findings
        if ctx.exploit_results:
            _wired = 0
            for _er in ctx.exploit_results:
                if _er.status != "success" or not _er.output_path:
                    continue
                _ef = _er.finding
                _er_rule = _ef.get("rule_id", "")
                _er_file = _ef.get("file", "")
                try:
                    with open(_er.output_path, "r", encoding="utf-8") as _fp:
                        _exploit_src = _fp.read()
                except Exception:
                    _exploit_src = ""
                for _uf in all_findings:
                    if getattr(_uf, "exploit_code", ""):
                        continue
                    if _uf.rule_id == _er_rule:
                        if (
                            _er_file
                            and _uf.file
                            and _er_file not in _uf.file
                            and _uf.file not in _er_file
                        ):
                            continue
                        _uf.exploit_code = _exploit_src
                        _uf.exploit_path = _er.output_path
                        _wired += 1
                        break
            ctx.logger.info("Wired %d exploit PoC(s) into unified findings", _wired)

        # Create audit report object
        project_name = ctx.args.project_name or os.path.basename(
            os.path.abspath(ctx.target)
        )
        audit_report = create_audit_report(
            project_name=project_name,
            target_path=ctx.target,
            findings=all_findings,
            engine_version=_ENGINE_VERSION,
            analyzer_status=ctx.analyzer_status,
        )

        # Markdown report (always free)
        md_file = str(ctx.scan_output_dir / "audit_report.md")
        md_path = generate_markdown_report(audit_report, md_file)
        print(f"\n[*] Professional Report Generated:")
        print(f"   Markdown: {os.path.abspath(md_path)}")
        ctx.logger.info("Professional Markdown report: %s", os.path.abspath(md_path))

        # HTML/PDF reports require Pro license
        from license_manager import LicenseManager, BRANDED_REPORTS
        _license = LicenseManager()
        if ctx.args.dev or _license.check_pro_feature(BRANDED_REPORTS):
            html_file = str(ctx.scan_output_dir / "audit_report.html")
            html_path = generate_html_report(audit_report, html_file, dev_mode=ctx.args.dev)
            if html_path:
                print(f"   HTML: {os.path.abspath(html_path)}")
                ctx.logger.info(
                    "Professional HTML report: %s", os.path.abspath(html_path)
                )

            pdf_file = str(ctx.scan_output_dir / "audit_report.pdf")
            pdf_path = generate_pdf_report(audit_report, pdf_file, dev_mode=ctx.args.dev)
            if pdf_path:
                print(f"   PDF:  {os.path.abspath(pdf_path)}")
                ctx.logger.info(
                    "Professional PDF report: %s", os.path.abspath(pdf_path)
                )
            else:
                ctx.logger.info(
                    "PDF report skipped "
                    "(install xhtml2pdf: pip install counterscarp-engine[pdf])"
                )
        else:
            ctx.logger.info(
                "HTML/PDF reports require Pro license: %s",
                _license.get_upgrade_message(BRANDED_REPORTS),
            )

        print(f"\n   Risk Score: {audit_report.risk_score}/100")
        print(f"   Status: {audit_report.pass_fail}")
        print(f"   Findings: {len(all_findings)} total")
        ctx.logger.info(
            "Audit Summary — Risk Score: %d/100, Status: %s, Findings: %d",
            audit_report.risk_score,
            audit_report.pass_fail,
            len(all_findings),
        )

        severity_counts: Dict[str, int] = {}
        for f in all_findings:
            sev = f.severity if hasattr(f, "severity") else "UNKNOWN"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        ctx.logger.info("Findings by severity: %s", severity_counts)

        return None  # ReportPhase does not produce findings
