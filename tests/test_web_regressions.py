"""Web-app bugs found by running real scans through the site."""

from __future__ import annotations

import asyncio
import io
import json
import re
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import UploadFile

SLITHER_ISSUE = {
    "title": "reentrancy-eth",
    "impact": "High",
    "description": "Reentrancy in Bank.withdraw()",
    "location": "src/Bank.sol (Lines: [12, 13, 14])",
}


def test_zip_upload_is_saved_without_text_validation(tmp_path: Path) -> None:
    from webapp.main import _save_upload_file_streaming

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/src/A.sol", "contract A {}\n")
    data = buf.getvalue()
    upload = UploadFile(filename="proj.zip", file=io.BytesIO(data))
    dest = tmp_path / "proj.zip"

    lines = asyncio.run(_save_upload_file_streaming(upload, dest))
    assert lines == 0
    assert dest.read_bytes() == data


def test_worker_turns_pipeline_slither_issues_into_findings(tmp_path: Path) -> None:
    import webapp.config as cfg
    from webapp import worker

    audit_id = "a1b2c3d4-0000-4000-8000-000000000001"
    upload_dir = tmp_path / "uploads" / audit_id
    upload_dir.mkdir(parents=True)
    sol = upload_dir / "Bank.sol"
    sol.write_text("pragma solidity ^0.8.0;\ncontract Bank {}\n", encoding="utf-8")

    def fake_context(**kwargs):
        return SimpleNamespace(
            heuristic_results=[], static_issues=[SLITHER_ISSUE], fingerprint_results=[],
            analyzer_status={"Slither (Static Analysis)": {"ran": True, "finding_count": 1, "error": None}},
        )

    async def fake_pipeline(ctx):
        return None

    with patch.object(cfg, "RESULTS_DIR", tmp_path / "results"), \
         patch.object(cfg, "UPLOAD_DIR", tmp_path / "uploads"), \
         patch("webapp.web_pipeline.build_web_scan_context", side_effect=fake_context), \
         patch("webapp.web_pipeline.run_web_pipeline", side_effect=fake_pipeline), \
         patch.object(worker, "_update_user_audit_index_worker"), \
         patch.object(worker, "_write_scan_index_worker"):
        asyncio.run(worker.run_audit({"job_try": 3}, audit_id, [str(sol)], "", ""))

    results = tmp_path / "results" / audit_id
    status = json.loads((results / "scan_status.json").read_text(encoding="utf-8"))
    assert status["status"] == "complete", status
    findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    slither = [f for f in findings if f["rule_id"] == "SLITHER-REENTRANCY-ETH"]
    assert slither and slither[0]["severity"] == "HIGH" and slither[0]["line_no"] == 12
    meta = json.loads((results / "scan_meta.json").read_text(encoding="utf-8"))
    by_name = {a["name"]: a for a in meta["analyzers"]}
    assert by_name["Slither Static Analysis"]["findings_count"] == 1


def test_worker_legacy_fallback_runs_when_pipeline_fails(tmp_path: Path) -> None:
    """The heuristic scanner was shadowed by the scan-target path string, so
    the fallback crashed with "'str' object is not callable"."""
    import webapp.config as cfg
    from webapp import worker

    audit_id = "a1b2c3d4-0000-4000-8000-000000000003"
    upload_dir = tmp_path / "uploads" / audit_id
    upload_dir.mkdir(parents=True)
    sol = upload_dir / "Bank.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\ncontract Bank {\n"
        "    address owner;\n"
        "    function f() external { require(tx.origin == owner); }\n}\n",
        encoding="utf-8",
    )

    with patch.object(cfg, "RESULTS_DIR", tmp_path / "results"), \
         patch.object(cfg, "UPLOAD_DIR", tmp_path / "uploads"), \
         patch("webapp.web_pipeline.build_web_scan_context", side_effect=RuntimeError("boom")), \
         patch("webapp.scan_utils.run_slither_analysis", return_value=([], "completed")), \
         patch.object(worker, "_update_user_audit_index_worker"), \
         patch.object(worker, "_write_scan_index_worker"):
        asyncio.run(worker.run_audit({"job_try": 3}, audit_id, [str(sol)], "", ""))

    results = tmp_path / "results" / audit_id
    status = json.loads((results / "scan_status.json").read_text(encoding="utf-8"))
    assert status["status"] == "complete", status
    findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    assert any(f["rule_id"] == "TX_ORIGIN_USAGE" for f in findings)


def test_attack_graph_page_gets_nonce_and_its_own_csp(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    import visualizer
    import webapp.main as main

    audit_id = "a1b2c3d4-0000-4000-8000-000000000002"
    results = tmp_path / audit_id
    results.mkdir()
    graph = {"nodes": [{"name": "x", "type": "Vulnerability", "severity": "HIGH"}], "links": []}
    page = visualizer.generate_attack_graph_html(graph, str(results / "attack_graph.html"))
    # Simulate an older graph file whose data line smuggled in a script tag.
    text = Path(page).read_text(encoding="utf-8")
    text = text.replace("const graphData = ", "const graphData = /*<script>evil()</script>*/ ", 1)
    Path(page).write_text(text, encoding="utf-8")

    with patch.object(main, "RESULTS_DIR", tmp_path):
        resp = TestClient(main.app).get(f"/results/{audit_id}/attack-graph")

    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert resp.text.count(f'nonce="{nonce}"') == 2  # d3 + the page script
    assert "<script>evil()" in resp.text  # left without a nonce, so CSP blocks it
    assert 'src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js"' in resp.text
    assert " onclick=" not in resp.text and " onchange=" not in resp.text
