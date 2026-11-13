"""Heuristic rules that flagged reviewed, safe code as HIGH (seen scanning Sigvara)."""

from __future__ import annotations

from pathlib import Path

from heuristic_scanner import scan_file, scan_target


def _severities(tmp_path: Path, body: str, rule_id: str) -> dict:
    path = tmp_path / "C.sol"
    path.write_text("pragma solidity ^0.8.24;\n" + body, encoding="utf-8")
    return {
        f.line_no: f.severity
        for f in scan_file(str(path))
        if f.rule_id == rule_id and not f.suppressed
    }


def _line_of(body: str, needle: str) -> int:
    return 1 + next(i for i, ln in enumerate(body.splitlines(), 1) if needle in ln)


class TestUnsafeCast:
    BODY = """contract C {
    function a(uint256 total) external pure returns (uint8) {
        assert(total <= 100);
        return uint8(total);
    }
    function b(uint256 until) external pure returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(until);
    }
    function c(uint256 v) external pure returns (uint16) {
        if (v > 1000) revert();
        return uint16(v);
    }
    function d(uint256 raw) external pure returns (uint8) {
        return uint8(raw);
    }
}
"""

    def test_bounded_or_reviewed_casts_are_info_and_raw_cast_stays_high(self, tmp_path: Path) -> None:
        sev = _severities(tmp_path, self.BODY, "UNSAFE_CAST")
        assert sev[_line_of(self.BODY, "uint8(total)")] == "INFO"
        assert sev[_line_of(self.BODY, "uint64(until)")] == "INFO"
        assert sev[_line_of(self.BODY, "uint16(v)")] == "INFO"
        assert sev[_line_of(self.BODY, "uint8(raw)")] == "HIGH"


class TestMint:
    CASES = {
        "constructor() { _mint(msg.sender, 1e24); }": "INFO",
        "function mint(address to, uint256 a) external onlyOwner { _mint(to, a); }": "MEDIUM",
        "function adminMint(address to, uint256 a) external {\n"
        "        require(msg.sender == owner, \"no\");\n        _mint(to, a);\n    }": "MEDIUM",
        "function faucet(uint256 a) external {\n"
        "        if (a > 10) revert(\"cap\");\n        _mint(msg.sender, a);\n    }": "MEDIUM",
        "function _reward(address to) internal { _mint(to, 1); }": "LOW",
        "function free(uint256 a) external { _mint(msg.sender, a); }": "HIGH",
    }

    def test_mints_are_graded_by_who_can_reach_them(self, tmp_path: Path) -> None:
        for fn, expected in self.CASES.items():
            body = f"contract T {{\n    address owner;\n    {fn}\n}}\n"
            sev = _severities(tmp_path, body, "HIDDEN_MINT")
            assert list(sev.values()) == [expected], (fn, sev)

    def test_nearby_duplicate_keeps_the_most_severe(self, tmp_path: Path) -> None:
        body = (
            "contract T {\n"
            "    function _reward(address to) internal { _mint(to, 1); }\n"
            "    function free(uint256 a) external { _mint(msg.sender, a); }\n"
            "}\n"
        )
        path = tmp_path / "T.sol"
        path.write_text("pragma solidity ^0.8.24;\n" + body, encoding="utf-8")
        mints = [f for f in scan_target(str(path)) if f.rule_id == "HIDDEN_MINT"]
        assert len(mints) == 1
        assert mints[0].severity == "HIGH" and mints[0].duplicate_count == 1


class TestTimestampRandomness:
    BODY = """contract R {
    uint256 owed; uint256 rate; uint256 nonce;
    function clock() external view returns (uint256) {
        return block.timestamp - (owed % 1 days) / rate;
    }
    function roll() external view returns (uint256) {
        return block.timestamp % 6;
    }
    function hashed() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, nonce))) % 6;
    }
    function reviewed() external view returns (uint256) {
        // slither-disable-next-line weak-prng
        return block.timestamp % 6;
    }
}
"""

    def test_only_timestamp_entropy_is_high(self, tmp_path: Path) -> None:
        sev = _severities(tmp_path, self.BODY, "BLOCK_TIMESTAMP_RANDOMNESS")
        assert sev[_line_of(self.BODY, "(owed % 1 days)")] == "INFO"
        assert sev[_line_of(self.BODY, "return block.timestamp % 6;")] == "HIGH"
        assert sev[_line_of(self.BODY, "keccak256(abi.encodePacked(block.timestamp")] == "HIGH"
        reviewed_line = _line_of(self.BODY, "// slither-disable-next-line weak-prng") + 1
        assert sev[reviewed_line] == "INFO"


def test_scan_target_skips_build_output_and_packages(tmp_path: Path, caplog) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract A { function f() external { require(tx.origin == msg.sender); } }\n"
    )
    # Forge writes artifacts as out/<Name>.sol/<Name>.json directories.
    (tmp_path / "out" / "A.sol").mkdir(parents=True)
    (tmp_path / "out" / "A.sol" / "A.json").write_text("{}")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "B.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract B { function g() external { require(tx.origin == msg.sender); } }\n"
    )
    findings = scan_target(str(tmp_path))
    files = {Path(f.file).relative_to(tmp_path).as_posix() for f in findings}
    assert files == {"src/A.sol"}
    assert "Failed to read file" not in caplog.text
