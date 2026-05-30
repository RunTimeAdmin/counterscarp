"""Tests for protocol fingerprint integration in scan_utils."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from webapp.scan_utils import run_protocol_fingerprint_analysis


def test_run_protocol_fingerprint_creates_match_finding(tmp_path) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\ncontract Token { function swap() external {} }\n",
        encoding="utf-8",
    )

    mock_matches = [
        {
            "protocol": "Uniswap V2",
            "confidence": 0.72,
            "risk_assessment": "HIGH - matches fork with known issues",
            "recommended_checks": ["[HIGH] Reentrancy in pair sync"],
            "known_vulnerabilities": [{"severity": "HIGH", "title": "Reentrancy"}],
        }
    ]

    with patch(
        "fingerprint_scanner.scan_for_protocol_similarity",
        return_value=mock_matches,
    ), patch(
        "fork_logic_checks.run_fork_checks",
        return_value=[],
    ), patch(
        "protocol_db.get_default_fingerprints",
        return_value=[MagicMock(), MagicMock()],
    ):
        findings, status, meta = run_protocol_fingerprint_analysis([str(sol)])

    assert status == "completed"
    assert meta["matches_found"] == 1
    assert len(findings) == 1
    assert findings[0].category == "Protocol Fingerprint"
    assert findings[0].severity == "MEDIUM"
    assert "Uniswap V2" in findings[0].title


def test_run_protocol_fingerprint_skips_non_solidity() -> None:
    findings, status, meta = run_protocol_fingerprint_analysis(["/tmp/Lib.rs"])
    assert findings == []
    assert status == "completed"
    assert meta.get("matches_found", 0) == 0
