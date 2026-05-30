"""Tests for Slither integration in scan_utils."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from webapp.scan_utils import (
    _is_slither_project_dir,
    run_slither_analysis,
)


def test_is_slither_project_dir_detects_foundry(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    assert _is_slither_project_dir(tmp_path) is True


def test_is_slither_project_dir_false_for_bare_upload(tmp_path: Path) -> None:
    (tmp_path / "Token.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    assert _is_slither_project_dir(tmp_path) is False


def test_run_slither_analysis_per_file_on_bare_directory(tmp_path: Path) -> None:
    sol = tmp_path / "Vulnerable.sol"
    sol.write_text("pragma solidity ^0.8.0;\ncontract C {}\n", encoding="utf-8")

    slither_json = (
        '{"results":{"detectors":[{"check":"reentrancy-eth","impact":"High",'
        '"description":"Reentrancy","elements":[{"source_mapping":'
        '{"filename_short":"Vulnerable.sol","lines":[1]},"name":"withdraw"}]}]}}'
    )
    mock_result = MagicMock(returncode=1, stdout=slither_json, stderr="")

    with patch("webapp.scan_utils._invoke_slither", return_value=mock_result):
        findings, status = run_slither_analysis(str(tmp_path), tmp_path)

    assert status == "completed"
    assert len(findings) == 1
    assert findings[0].rule_id == "SLITHER-REENTRANCY-ETH"
    assert findings[0].severity == "HIGH"


def test_run_slither_analysis_not_installed(tmp_path: Path) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text("pragma solidity ^0.8.0;\ncontract C {}\n", encoding="utf-8")

    with patch(
        "webapp.scan_utils._invoke_slither",
        side_effect=FileNotFoundError("slither"),
    ):
        findings, status = run_slither_analysis(str(sol), tmp_path)

    assert status == "not_installed"
    assert findings == []


def test_run_slither_analysis_skips_non_sol_file(tmp_path: Path) -> None:
    rs = tmp_path / "lib.rs"
    rs.write_text("fn main() {}\n", encoding="utf-8")
    findings, status = run_slither_analysis(str(rs), tmp_path)
    assert status == "skipped"
    assert findings == []


def test_run_slither_analysis_rejects_path_outside_upload(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    outside = tmp_path / "outside.sol"
    outside.write_text("pragma solidity ^0.8.0;\ncontract C {}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside upload directory"):
        run_slither_analysis(str(outside), upload_dir)
