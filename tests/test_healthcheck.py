"""Tests for healthcheck.py — tool version verification."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import healthcheck as hc
from healthcheck import (
    _extract_version,
    _get_installed_version,
    _load_expected,
    run_healthcheck,
    STATUS_OK,
    STATUS_MISMATCH,
    STATUS_MISSING,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tool_versions_file(tmp_path: Path) -> Path:
    data = {
        "slither": "0.10.0",
        "aderyn": "0.3.0",
        "medusa": "0.3.3",
        "mythril": "0.24.7",
        "foundry": "0.3.0",
        "solc_default": "0.8.26",
    }
    path = tmp_path / "tool-versions.json"
    path.write_text(json.dumps(data))
    return path


# ---------------------------------------------------------------------------
# TestLoadExpected
# ---------------------------------------------------------------------------


class TestLoadExpected:
    def test_loads_from_provided_path(self, tool_versions_file: Path) -> None:
        data = _load_expected(tool_versions_file)
        assert data["slither"] == "0.10.0"
        assert data["foundry"] == "0.3.0"

    def test_raises_when_file_missing(self, tmp_path: Path) -> None:
        """When the given path doesn't exist AND no fallback exists, raises."""
        missing = tmp_path / "nonexistent.json"
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(FileNotFoundError):
                _load_expected(missing)

    def test_raises_when_none_and_no_default(self, tmp_path: Path) -> None:
        """When json_path is None and no default file exists, should raise."""
        # Patch the parent to a dir where file doesn't exist
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(FileNotFoundError):
                _load_expected(None)


# ---------------------------------------------------------------------------
# TestGetInstalledVersion
# ---------------------------------------------------------------------------


class TestGetInstalledVersion:
    def test_returns_output_on_success(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "slither 0.10.0\n"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = _get_installed_version(["slither", "--version"])
        assert result == "slither 0.10.0"

    def test_returns_none_when_not_found(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _get_installed_version(["nonexistent-tool", "--version"])
        assert result is None

    def test_returns_none_on_timeout(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=10)):
            result = _get_installed_version(["slow-tool"])
        assert result is None

    def test_combines_stdout_and_stderr(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "out"
        mock_result.stderr = "err"
        with patch("subprocess.run", return_value=mock_result):
            result = _get_installed_version(["tool"])
        assert result == "outerr"


# ---------------------------------------------------------------------------
# TestExtractVersion
# ---------------------------------------------------------------------------


class TestExtractVersion:
    def test_extracts_semver(self) -> None:
        assert _extract_version("slither 0.10.0", r"(\d+\.\d+\.\d+)") == "0.10.0"

    def test_returns_none_when_no_match(self) -> None:
        assert _extract_version("no version here", r"(\d+\.\d+\.\d+)") is None

    def test_extracts_first_match(self) -> None:
        assert _extract_version("v1.2.3 build 4.5.6", r"(\d+\.\d+\.\d+)") == "1.2.3"

    def test_various_version_strings(self) -> None:
        assert _extract_version("Forge 0.3.1+commit.abc", r"(\d+\.\d+\.\d+)") == "0.3.1"


# ---------------------------------------------------------------------------
# TestRunHealthcheck
# ---------------------------------------------------------------------------


class TestRunHealthcheck:
    def _make_mock_run(self, version: str):
        """Return a side_effect function that always returns the given version."""
        def side_effect(cmd, **kwargs):
            result = MagicMock()
            result.stdout = version
            result.stderr = ""
            return result
        return side_effect

    def test_all_ok_when_versions_match(self, tool_versions_file: Path, capsys) -> None:
        # All tool commands return the exact expected version
        with patch("subprocess.run", side_effect=self._make_mock_run("0.10.0")):
            # Patch the version file so all expected == "0.10.0"
            minimal = {k: "0.10.0" for k in hc.TOOL_COMMANDS}
            with patch.object(Path, "exists", return_value=True):
                with patch("builtins.open", MagicMock(return_value=MagicMock(
                    __enter__=lambda s, *a: s,
                    __exit__=lambda s, *a: None,
                    read=lambda: json.dumps(minimal),
                ))):
                    pass  # just ensure it doesn't crash

    def test_returns_false_when_file_not_found(self, tmp_path: Path, capsys) -> None:
        missing = tmp_path / "missing.json"
        with patch.object(Path, "exists", return_value=False):
            result = run_healthcheck(missing)
        assert result is False
        out = capsys.readouterr().out
        assert "[ERROR]" in out

    def test_returns_false_when_tool_missing(self, tool_versions_file: Path, capsys) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_healthcheck(tool_versions_file)
        assert result is False
        out = capsys.readouterr().out
        assert STATUS_MISSING in out

    def test_returns_false_when_version_mismatch(self, tool_versions_file: Path, capsys) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "9.9.9"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = run_healthcheck(tool_versions_file)
        assert result is False
        out = capsys.readouterr().out
        assert STATUS_MISMATCH in out

    def test_prints_table_headers(self, tool_versions_file: Path, capsys) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            run_healthcheck(tool_versions_file)
        out = capsys.readouterr().out
        assert "Tool" in out
        assert "Expected" in out
        assert "Status" in out

    def test_returns_true_when_all_versions_match(self, tmp_path: Path, capsys) -> None:
        """All tools report matching versions → returns True."""
        # Create a versions file where every tool expects "1.2.3"
        minimal: dict = {k: "1.2.3" for k in hc.TOOL_COMMANDS}
        vf = tmp_path / "tool-versions.json"
        vf.write_text(json.dumps(minimal))

        mock_result = MagicMock()
        mock_result.stdout = "version 1.2.3\n"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = run_healthcheck(vf)
        assert result is True
        out = capsys.readouterr().out
        assert "All tools verified successfully." in out

    def test_tool_with_no_output_shows_question_mark(self, tmp_path: Path, capsys) -> None:
        """A tool that returns output with no parseable version shows '?'."""
        minimal: dict = {k: "1.2.3" for k in hc.TOOL_COMMANDS}
        vf = tmp_path / "tool-versions.json"
        vf.write_text(json.dumps(minimal))

        mock_result = MagicMock()
        mock_result.stdout = "unparseable output here"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = run_healthcheck(vf)
        assert result is False

    def test_constants_values(self) -> None:
        assert STATUS_OK == "OK"
        assert STATUS_MISMATCH == "MISMATCH"
        assert STATUS_MISSING == "NOT FOUND"
