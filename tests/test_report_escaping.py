"""Finding text comes from scanned code, so HTML outputs must escape it."""

from __future__ import annotations

from pathlib import Path

from report_generator import AuditReport, Finding, ReportSection, generate_html_report

PAYLOAD = "<script>alert(1)</script>"


def test_html_report_escapes_finding_and_project_fields(tmp_path: Path) -> None:
    finding = Finding(
        rule_id=f"R-{PAYLOAD}",
        severity="HIGH",
        category=PAYLOAD,
        title=PAYLOAD,
        description=f"desc {PAYLOAD}",
        file=f"src/{PAYLOAD}.sol",
        line_no=7,
        code_snippet=f"function x() {{ /* {PAYLOAD} */ }}",
        remediation=PAYLOAD,
        references=["javascript:alert(1)", "https://example.com/?a=<b>"],
        similar_locations=[f"{PAYLOAD}:1"],
        duplicate_count=1,
        rag_remediation=PAYLOAD,
        rag_references=[{"url": "javascript:alert(2)", "source": PAYLOAD}],
    )
    report = AuditReport(
        project_name=PAYLOAD,
        target_path=PAYLOAD,
        timestamp="2026-11-12",
        engine_version="test",
        executive_summary={"HIGH": 1},
        sections=[ReportSection(title=PAYLOAD, findings=[finding], summary=PAYLOAD)],
        risk_score=50.0,
        pass_fail="FAIL",
    )
    out = generate_html_report(report, str(tmp_path / "r.html"), dev_mode=True)
    html = Path(out).read_text(encoding="utf-8")

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'href="javascript:' not in html
    assert 'href="https://example.com/?a=&lt;b&gt;"' in html


def test_attack_graph_page_escapes_node_data(tmp_path: Path) -> None:
    import visualizer

    graph = {"nodes": [{"name": "</script><script>alert(1)</script>"}], "links": []}
    out = visualizer.generate_attack_graph_html(graph, str(tmp_path / "g.html"))
    page = Path(out).read_text(encoding="utf-8")
    assert "<script>alert(1)" not in page
    assert "function esc(" in page and "esc(node.description" in page
