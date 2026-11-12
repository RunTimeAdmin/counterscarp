"""Reports must not claim results for analyzers that did not run."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import aderyn_wrapper
from orchestrator import (
    _aggregate_findings,
    _compute_risk_metrics,
    _empty_section_text,
    _generate_action_plan_report,
)

ADERYN_JSON = {
    "files_summary": {"total_source_units": 1},
    "issue_count": {"high": 1, "low": 1},
    "high_issues": {"issues": [{
        "title": "Reentrancy", "description": "State change after call",
        "detector_name": "reentrancy-state-change",
        "instances": [
            {"contract_path": "src/Bank.sol", "line_no": 12},
            {"contract_path": "src/Bank.sol", "line_no": 30},
        ],
    }]},
    "low_issues": {"issues": [{
        "title": "Unspecific pragma", "description": "Pin the version",
        "detector_name": "unspecific-solidity-pragma",
        "instances": [{"contract_path": "src/Bank.sol", "line_no": 2}],
    }]},
}


class TestAderyn:
    def test_parse_flattens_every_instance(self) -> None:
        parsed = aderyn_wrapper.parse_aderyn_output(json.dumps(ADERYN_JSON), "")
        assert parsed["total"] == 2
        assert [(i["severity"], i["line_no"]) for i in parsed["issues"]] == [
            ("HIGH", 12), ("HIGH", 30), ("LOW", 2),
        ]
        assert parsed["issues"][0]["file"] == "src/Bank.sol"

    def test_run_reads_json_report_file_not_stdout(self, tmp_path: Path) -> None:
        def fake_run(cmd, **kwargs):
            out = Path(cmd[cmd.index("--output") + 1])
            assert out.suffix == ".json" and tmp_path not in out.parents
            out.write_text(json.dumps(ADERYN_JSON), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Detectors run, processing found issues\n", stderr="")

        with patch.object(aderyn_wrapper, "check_aderyn_installed", return_value=True), \
             patch.object(aderyn_wrapper.subprocess, "run", side_effect=fake_run):
            result = aderyn_wrapper.run_aderyn(str(tmp_path))
        assert len(result["issues"]) == 3

    def test_missing_report_is_an_error_not_zero_findings(self, tmp_path: Path) -> None:
        import pytest
        from exceptions import CounterscarpAnalysisError

        with patch.object(aderyn_wrapper, "check_aderyn_installed", return_value=True), \
             patch.object(aderyn_wrapper.subprocess, "run",
                          return_value=MagicMock(returncode=1, stdout="", stderr="compile failed")):
            with pytest.raises(CounterscarpAnalysisError):
                aderyn_wrapper.run_aderyn(str(tmp_path))

    def test_aggregation_counts_aderyn_instances(self) -> None:
        parsed = aderyn_wrapper.parse_aderyn_output(json.dumps(ADERYN_JSON), "")
        findings = _aggregate_findings([], [], [], [], [], aderyn_results=parsed)
        assert sorted(f["severity"] for f in findings) == ["HIGH", "HIGH", "LOW"]


class TestEmptySections:
    def test_states(self) -> None:
        status = {
            "Ran": {"ran": True, "finding_count": 0, "error": None},
            "Failed": {"ran": False, "error": "compile error"},
            "Skipped": {"ran": False, "error": None, "skipped": "no package.json"},
        }
        assert _empty_section_text(status, ("Ran",), "X", "Clean.").startswith("[OK] Clean.")
        assert "did not complete** (compile error)" in _empty_section_text(status, ("Failed",), "X", "Clean.")
        assert "skipped (no package.json)" in _empty_section_text(status, ("Skipped",), "X", "Clean.")
        assert "was not run" in _empty_section_text(status, ("Absent",), "X", "Clean.")

    def test_action_plan_does_not_claim_unrun_checks(self, tmp_path: Path) -> None:
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            path = _generate_action_plan_report(
                project_name="p", static_results=[], supply_results=[],
                fuzz_results=[], heuristic_results=[], symbolic_results=[],
                analyzer_status={
                    "Slither (Static Analysis)": {"ran": False, "error": "solc mismatch"},
                    "Supply Chain": {"ran": False, "error": None, "skipped": "no package.json"},
                },
            )
            text = Path(path).read_text(encoding="utf-8")
        finally:
            os.chdir(cwd)
        for claim in ("up to date", "held up against stress", "No issues reported by Mythril",
                      "No critical patterns"):
            assert claim not in text
        assert "Slither did not complete** (solc mismatch)" in text
        assert "Fuzzing was not run" in text


class TestStatus:
    def test_high_findings_are_not_stable(self) -> None:
        findings = [{"severity": "HIGH"}] * 7
        metrics = _compute_risk_metrics(findings)
        assert metrics["status_icon"] == "[HIGH RISK]"
        assert metrics["critical_count"] == 0

    def test_slither_medium_stays_medium(self) -> None:
        findings = _aggregate_findings(
            [{"impact": "Medium", "check": "x"}, {"impact": "Informational", "check": "y"}],
            [], [], [], [],
        )
        assert [f["severity"] for f in findings] == ["MEDIUM", "INFO"]
