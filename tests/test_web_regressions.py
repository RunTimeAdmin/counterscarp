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


def test_web_outputs_do_not_show_the_server_upload_folder(tmp_path: Path) -> None:
    """Heuristic findings and the report's Target line used to carry the full
    upload path (on the server, its folder layout)."""
    import webapp.config as cfg
    from webapp import worker

    audit_id = "a1b2c3d4-0000-4000-8000-000000000004"
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
         patch("red_team_scan.run_slither", return_value={"success": True, "results": {}}), \
         patch.object(worker, "_update_user_audit_index_worker"), \
         patch.object(worker, "_write_scan_index_worker"):
        asyncio.run(worker.run_audit({"job_try": 3}, audit_id, [str(sol)], "", ""))

    results = tmp_path / "results" / audit_id
    findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    tx_origin = [f for f in findings if f["rule_id"] == "TX_ORIGIN_USAGE"]
    assert tx_origin and tx_origin[0]["file"] == "Bank.sol"
    assert "**Target:** `Bank.sol`" in (results / "report.md").read_text(encoding="utf-8")
    server_paths = {str(tmp_path), tmp_path.as_posix(), json.dumps(str(tmp_path))[1:-1]}
    for out in results.iterdir():
        text = out.read_text(encoding="utf-8", errors="replace")
        assert not any(p in text for p in server_paths), out.name


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


def _settings_post_as(email: str, monkeypatch, tmp_path: Path):
    """Log in as *email* (get_current_user mocked), load /settings for a CSRF
    token, then post a new OpenAI key."""
    from fastapi.testclient import TestClient

    import webapp.main as main

    monkeypatch.setenv("OPENAI_API_KEY", "sk-operator-key")
    written: list = []
    user = {"id": "u1", "email": email, "name": ""}
    with patch.object(main, "get_current_user", return_value=user), \
         patch.object(main, "ADMIN_EMAIL", "admin@example.com"), \
         patch.object(main._license, "get_tier", return_value="pro"), \
         patch.object(main, "write_private_file", side_effect=lambda p, t: written.append(t)):
        client = TestClient(main.app)
        page = client.get("/settings")
        token = re.search(
            r"""(?:name="_csrf_token" value="|encodeURIComponent\(')([^"']+)""", page.text
        ).group(1)
        resp = client.post(
            "/settings/api-key",
            data={"_csrf_token": token, "openai_api_key": "sk-attacker-key"},
            follow_redirects=False,
        )
        test_resp = client.post("/settings/test-key", json={"key": "sk-any"})
    return page, resp, test_resp, written


def test_only_the_admin_can_replace_the_server_openai_key(monkeypatch, tmp_path: Path) -> None:
    """Any signed-up user could overwrite the server-wide key used for every scan."""
    import os

    page, resp, test_resp, written = _settings_post_as("someone@example.com", monkeypatch, tmp_path)
    assert resp.status_code == 403
    assert test_resp.status_code == 403
    assert os.environ["OPENAI_API_KEY"] == "sk-operator-key" and not written
    assert 'action="/settings/api-key"' not in page.text

    page, resp, _, written = _settings_post_as("admin@example.com", monkeypatch, tmp_path)
    assert resp.status_code == 303
    assert os.environ["OPENAI_API_KEY"] == "sk-attacker-key" and written
    assert 'action="/settings/api-key"' in page.text


def test_scan_without_solidity_fails_with_a_reason_instead_of_looking_clean(tmp_path: Path) -> None:
    """A Rust-only upload reported every analyzer as "completed, 0 findings"."""
    import webapp.config as cfg
    from webapp import worker

    audit_id = "a1b2c3d4-0000-4000-8000-000000000006"
    upload_dir = tmp_path / "uploads" / audit_id
    upload_dir.mkdir(parents=True)
    rs = upload_dir / "lib.rs"
    rs.write_text("pub fn withdraw() {}\n")

    with patch.object(cfg, "RESULTS_DIR", tmp_path / "results"), \
         patch.object(cfg, "UPLOAD_DIR", tmp_path / "uploads"), \
         patch("webapp.web_pipeline.run_web_pipeline") as pipeline, \
         patch.object(worker, "_update_user_audit_index_worker"), \
         patch.object(worker, "_write_scan_index_worker"):
        asyncio.run(worker.run_audit({"job_try": 3}, audit_id, [str(rs)], "", ""))

    status = json.loads((tmp_path / "results" / audit_id / "scan_status.json").read_text())
    assert status["status"] == "failed"
    assert status["progress"] == cfg.NO_SOLIDITY_MESSAGE
    pipeline.assert_not_called()

    # A project whose only Solidity is its dependencies has nothing of its own to scan.
    proj = tmp_path / "proj"
    (proj / "lib" / "dep").mkdir(parents=True)
    (proj / "lib" / "dep" / "Dep.sol").write_text("contract Dep {}\n")
    assert worker._has_solidity(proj, ["lib"]) is False
    (proj / "src").mkdir()
    (proj / "src" / "A.sol").write_text("contract A {}\n")
    assert worker._has_solidity(proj, ["lib"]) is True


def test_upload_form_refuses_rust_files(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    import webapp.config as cfg
    import webapp.main as main
    import webapp.routes.audit as audit_route

    with patch.object(audit_route, "UPLOAD_DIR", tmp_path / "u"), \
         patch.object(audit_route, "RESULTS_DIR", tmp_path / "r"):
        client = TestClient(main.app)
        page = client.get("/")
        token = re.search(r'name="_csrf_token" value="([^"]+)"', page.text).group(1)
        resp = client.post(
            "/audit",
            data={"_csrf_token": token, "project_name": "x"},
            files={"files": ("lib.rs", b"pub fn f() {}\n", "text/plain")},
        )
    assert resp.status_code == 400
    assert cfg.NO_SOLIDITY_MESSAGE in resp.text
    assert 'accept=".sol,.zip"' in page.text
