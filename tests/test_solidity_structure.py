"""Tests for solidity_structure module."""

from __future__ import annotations

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solidity_structure import (
    function_containing_line,
    parse_solidity_structure,
    strip_solidity_comments,
)


SAMPLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function transfer(address to, uint256 amount) external;
}

contract Vault is IToken {
    uint256 public balance;

    function deposit() external {
        balance = 1;
    }

    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok);
    }
}
"""


class TestStripSolidityComments:
    def test_removes_line_comments(self):
        cleaned = strip_solidity_comments("uint x; // hidden")
        assert "// hidden" not in cleaned
        assert "uint x;" in cleaned


class TestParseSolidityStructure:
    def test_finds_contract_and_interface(self):
        parsed = parse_solidity_structure(SAMPLE)
        names = {item["name"] for item in parsed["contracts"]}
        assert "Vault" in names
        assert "IToken" in names

    def test_functions_are_contract_scoped(self):
        parsed = parse_solidity_structure(SAMPLE)
        vault_funcs = [
            func for func in parsed["functions"] if func["contract"] == "Vault"
        ]
        assert {func["name"] for func in vault_funcs} == {"deposit", "withdraw"}

    def test_ignores_commented_function(self):
        content = """
contract Test {
    // function fake() external {}
    function real() external {}
}
"""
        parsed = parse_solidity_structure(content)
        assert [func["name"] for func in parsed["functions"]] == ["real"]

    def test_external_call_detected_in_withdraw(self):
        parsed = parse_solidity_structure(SAMPLE)
        calls = [
            call for call in parsed["external_calls"]
            if call["contract"] == "Vault"
        ]
        assert len(calls) == 1
        assert calls[0]["call_type"] == "call"

    def test_function_containing_line_picks_innermost(self):
        parsed = parse_solidity_structure(SAMPLE)
        withdraw = next(func for func in parsed["functions"] if func["name"] == "withdraw")
        call_line = next(
            call["line"] for call in parsed["external_calls"]
            if call["contract"] == "Vault"
        )
        containing = function_containing_line(parsed["functions"], call_line)
        assert containing is not None
        assert containing["name"] == "withdraw"
        assert containing["line"] == withdraw["line"]
