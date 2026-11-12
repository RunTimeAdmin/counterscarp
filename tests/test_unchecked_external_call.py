"""UNCHECKED_EXTERNAL_CALL must follow what each call returns and how it is used."""

from __future__ import annotations

from pathlib import Path

import pytest

from heuristic_scanner import scan_file


def _unchecked(tmp_path: Path, body: str) -> list:
    contract = (
        "pragma solidity ^0.8.0;\n"
        "interface IERC20 { function transfer(address, uint256) external returns (bool); "
        "function transferFrom(address, address, uint256) external returns (bool); }\n"
        "contract T {\n"
        "    IERC20 token;\n"
        "    error Failed();\n"
        "    function f(address payable to, uint256 amt) external {\n"
        f"{body}\n"
        "    }\n"
        "}\n"
    )
    path = tmp_path / "T.sol"
    path.write_text(contract, encoding="utf-8")
    return [
        (f.severity, f.line_text.strip())
        for f in scan_file(str(path))
        if f.rule_id == "UNCHECKED_EXTERNAL_CALL" and not f.suppressed
    ]


@pytest.mark.parametrize("body", [
    "        to.transfer(amt);",
    "        payable(msg.sender).transfer(address(this).balance);",
    "        to.transfer(\n            amt\n        );",
])
def test_eth_transfer_reverts_so_is_not_unchecked(tmp_path: Path, body: str) -> None:
    assert _unchecked(tmp_path, body) == []


def test_eth_transfer_is_still_reported_as_a_dos_risk(tmp_path: Path) -> None:
    path = tmp_path / "T.sol"
    path.write_text(
        "pragma solidity ^0.8.0;\ncontract T { function f(address payable to) external "
        "{\n        to.transfer(1);\n    } }\n",
        encoding="utf-8",
    )
    assert any(f.rule_id == "TRANSFER_DOSABLE_FALLBACK" for f in scan_file(str(path)))


@pytest.mark.parametrize("body", [
    "        token.transfer(to, amt);",
    "        token.transferFrom(msg.sender, to, amt);",
    "        to.send(amt);",
    '        to.call{value: amt}("");',
    "        token.transfer(\n            to,\n            amt\n        );",
])
def test_ignored_result_stays_flagged(tmp_path: Path, body: str) -> None:
    findings = _unchecked(tmp_path, body)
    assert findings and findings[0][0] == "CRITICAL", findings


@pytest.mark.parametrize("body", [
    "        require(token.transfer(to, amt));",
    "        require(to.send(amt), \"send failed\");",
    "        if (!token.transferFrom(msg.sender, to, amt)) revert Failed();",
    '        (bool ok, ) = to.call{value: amt}("");\n        require(ok);',
    '        (bool ok, ) = to.call{value: amt}("");\n        if (!ok) revert Failed();',
    "        bool sent = to.send(amt);\n        if (!sent) revert Failed();",
    '        (bool ok, ) =\n            to.call{value: amt}("");\n        require(ok, "call failed");',
])
def test_checked_result_is_info(tmp_path: Path, body: str) -> None:
    findings = _unchecked(tmp_path, body)
    assert findings and all(sev == "INFO" for sev, _ in findings), findings


@pytest.mark.parametrize("body", [
    '        (bool ok, ) = to.call{value: amt}("");',
    '        (, bytes memory data) = to.call{value: amt}("");\n        data;',
])
def test_captured_but_unused_result_is_high(tmp_path: Path, body: str) -> None:
    findings = _unchecked(tmp_path, body)
    assert findings and findings[0][0] == "HIGH", findings
