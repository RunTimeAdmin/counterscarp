"""Tests for agent-facing plain-text scan summaries."""

from __future__ import annotations

from webapp.scan_utils import format_agent_scan_summary


def test_format_pending_scan() -> None:
    text = format_agent_scan_summary(
        "abc-123",
        project_name="Token.sol",
        status="pending",
        findings_data=[],
    )
    assert "Scan still running" in text
    assert "abc-123" in text


def test_format_complete_scan_with_high_finding() -> None:
    findings = [
        {
            "rule_id": "SLITHER-REENTRANCY-ETH",
            "severity": "HIGH",
            "title": "Reentrancy Eth",
            "description": "External call before state update",
            "line_no": 12,
        },
        {
            "rule_id": "UNCHECKED_EXTERNAL_CALL",
            "severity": "INFO",
            "title": "Unchecked External Call",
            "description": "External call pattern",
            "line_no": 12,
        },
    ]
    text = format_agent_scan_summary(
        "abc-123",
        project_name="Vulnerable.sol",
        status="complete",
        findings_data=findings,
        analyzers=[
            {"name": "Heuristic Pattern Scanner", "status": "completed"},
            {"name": "Slither Static Analysis", "status": "completed"},
        ],
    )
    assert text.startswith("ScarpShield scan complete — Vulnerable.sol")
    assert "Audit ID: abc-123" in text
    assert "Risk score:" in text
    assert "[HIGH] Reentrancy Eth" in text
    assert "Slither ✓" in text
    assert "/report/html" in text


def test_format_zero_findings() -> None:
    text = format_agent_scan_summary(
        "abc-123",
        project_name="Clean.sol",
        status="complete",
        findings_data=[],
    )
    assert "No issues detected" in text
