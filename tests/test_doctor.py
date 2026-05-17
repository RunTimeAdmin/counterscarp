"""Tests for the doctor.py environment diagnostic module."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# Ensure the sentinel-engine root is on sys.path so `import doctor` works
import pathlib
_ENGINE_ROOT = str(pathlib.Path(__file__).parent.parent)
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

import doctor


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------


class TestParseSemver:
    def test_full_version(self):
        assert doctor._parse_semver("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert doctor._parse_semver("2.5") == (2, 5, 0)

    def test_version_with_prefix(self):
        assert doctor._parse_semver("v0.11.5") == (0, 11, 5)

    def test_version_embedded_in_text(self):
        assert doctor._parse_semver("slither 0.11.5 (git+…)") == (0, 11, 5)

    def test_no_version_returns_zeros(self):
        assert doctor._parse_semver("no version here") == (0, 0, 0)

    def test_single_digit(self):
        assert doctor._parse_semver("42") == (42, 0, 0)


class TestVersionOk:
    def test_equal_versions(self):
        assert doctor._version_ok("0.11.5", "0.11.5") is True

    def test_installed_greater(self):
        assert doctor._version_ok("0.12.0", "0.11.5") is True

    def test_installed_less(self):
        assert doctor._version_ok("0.11.4", "0.11.5") is False

    def test_major_upgrade_ok(self):
        assert doctor._version_ok("1.0.0", "0.24.8") is True

    def test_patch_less(self):
        assert doctor._version_ok("0.24.7", "0.24.8") is False


# ---------------------------------------------------------------------------
# _run_cmd helper
# ---------------------------------------------------------------------------


class TestRunCmd:
    def test_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="slither 0.11.5\n", stderr="", returncode=0
            )
            ok, output = doctor._run_cmd(["slither", "--version"])
        assert ok is True
        assert "0.11.5" in output

    def test_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            ok, output = doctor._run_cmd(["nonexistent_tool"])
        assert ok is False
        assert output == "NOT_FOUND"

    def test_timeout(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=10)):
            ok, output = doctor._run_cmd(["slow_tool"])
        assert ok is False
        assert output == "TIMEOUT"

    def test_generic_error(self):
        with patch("subprocess.run", side_effect=RuntimeError("boom")):
            ok, output = doctor._run_cmd(["broken"])
        assert ok is False
        assert "ERROR" in output


# ---------------------------------------------------------------------------
# _check_tool
# ---------------------------------------------------------------------------


class TestCheckTool:
    def test_tool_not_on_path_returns_missing(self):
        with patch("shutil.which", return_value=None):
            result = doctor._check_tool(
                "Slither", "slither", ["--version"], r"(\d+\.\d+\.\d+)",
                "0.11.5", "Static analysis", is_core=True
            )
        assert result["status"] == "MISSING"
        assert result["found"] is False
        assert result["is_core"] is True

    def test_tool_found_correct_version(self):
        with patch("shutil.which", return_value="/usr/bin/slither"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="slither 0.11.5\n", stderr="", returncode=0
            )
            result = doctor._check_tool(
                "Slither", "slither", ["--version"], r"(\d+\.\d+\.\d+)",
                "0.11.5", "Static analysis", is_core=True
            )
        assert result["status"] == "OK"
        assert result["version"] == "0.11.5"

    def test_tool_found_outdated_version(self):
        with patch("shutil.which", return_value="/usr/bin/slither"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="slither 0.10.0\n", stderr="", returncode=0
            )
            result = doctor._check_tool(
                "Slither", "slither", ["--version"], r"(\d+\.\d+\.\d+)",
                "0.11.5", "Static analysis", is_core=True
            )
        assert result["status"] == "OUTDATED"
        assert result["version"] == "0.10.0"

    def test_tool_crash_during_version_check(self):
        with patch("shutil.which", return_value="/usr/bin/slither"), \
             patch("subprocess.run", side_effect=FileNotFoundError()):
            result = doctor._check_tool(
                "Slither", "slither", ["--version"], r"(\d+\.\d+\.\d+)",
                "0.11.5", "Static analysis", is_core=True
            )
        assert result["status"] == "ERROR"

    def test_tool_with_no_min_version(self):
        with patch("shutil.which", return_value="/usr/bin/solc"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Version: 0.8.33+commit.xyz\n", stderr="", returncode=0
            )
            result = doctor._check_tool(
                "solc", "solc", ["--version"],
                r"Version:\s*(\d+\.\d+\.\d+)", "0.8.0", "Solidity compiler"
            )
        assert result["status"] == "OK"
        assert result["version"] == "0.8.33"

    def test_aderyn_binary_detected_but_not_on_path(self):
        with patch("shutil.which", return_value=None), \
             patch("doctor._find_binary_candidates", return_value=["/root/.cyfrin/bin/aderyn"]):
            result = doctor._check_tool(
                "Aderyn", "aderyn", ["--version"], r"(\d+\.\d+\.\d+)",
                "0.6.2", "See QUICKSTART.md", is_core=False
            )
        assert result["status"] == "ERROR"
        assert result["found"] is True
        assert "not on PATH" in result["notes"]


# ---------------------------------------------------------------------------
# _check_python_package
# ---------------------------------------------------------------------------


class TestCheckPythonPackage:
    def test_package_present(self):
        with patch("importlib.metadata.version", return_value="2.2.2"):
            result = doctor._check_python_package("sentence-transformers", "(RAG engine)")
        assert result["status"] == "OK"
        assert result["version"] == "2.2.2"

    def test_package_missing(self):
        with patch("importlib.metadata.version", side_effect=Exception("not found")):
            result = doctor._check_python_package("sentence-transformers", "(RAG engine)")
        assert result["status"] == "MISSING"
        assert result["version"] is None


# ---------------------------------------------------------------------------
# run_doctor integration test (all mocked)
# ---------------------------------------------------------------------------


def _make_tool_mock(version_str: str):
    """Return a mock subprocess.run result yielding *version_str*."""
    return MagicMock(stdout=version_str, stderr="", returncode=0)


class TestRunDoctor:
    """Integration test: mock all subprocesses and verify returned dict."""

    def _patch_all_found(self):
        """Context-manager patches that make every tool appear installed & up-to-date."""
        tool_outputs = {
            "slither": "0.11.5",
            "myth":    "mythril version 0.24.8",
            "medusa":  "medusa version 0.1.8",
            "aderyn":  "aderyn 0.6.2",
            "forge":   "forge Version: 1.6.0",
            "solc":    "Version: 0.8.33+commit.abc",
            "go":      "go version go1.21.0 linux/amd64",
        }

        def fake_which(cmd: str):
            return f"/usr/bin/{cmd}"

        def fake_run(cmd, **kwargs):
            binary = cmd[0]
            text = tool_outputs.get(binary, "")
            return MagicMock(stdout=text, stderr="", returncode=0)

        return (
            patch("shutil.which", side_effect=fake_which),
            patch("subprocess.run", side_effect=fake_run),
            patch("importlib.metadata.version", return_value="1.0.0"),
        )

    def test_returns_dict_with_expected_keys(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            result = doctor.run_doctor()

        assert isinstance(result, dict)
        assert "tools" in result
        assert "python" in result
        assert "go" in result
        assert "packages" in result
        assert "all_core_ok" in result
        assert "exit_code" in result

    def test_all_tools_ok_exit_code_0(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            result = doctor.run_doctor()
        assert result["all_core_ok"] is True
        assert result["exit_code"] == 0

    def test_core_tool_missing_exit_code_1(self, capsys):
        def fake_which(cmd: str):
            # slither is missing
            if cmd == "slither":
                return None
            return f"/usr/bin/{cmd}"

        tool_outputs = {
            "myth":   "mythril version 0.24.8",
            "medusa": "medusa version 0.1.8",
            "aderyn": "aderyn 0.6.2",
            "forge":  "forge Version: 1.6.0",
            "solc":   "Version: 0.8.33",
            "go":     "go version go1.21.0",
        }

        def fake_run(cmd, **kwargs):
            binary = cmd[0]
            text = tool_outputs.get(binary, "")
            return MagicMock(stdout=text, stderr="", returncode=0)

        with patch("shutil.which", side_effect=fake_which), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("importlib.metadata.version", return_value="1.0.0"):
            result = doctor.run_doctor()

        assert result["all_core_ok"] is False
        assert result["exit_code"] == 1
        slither_status = next(r for r in result["tools"] if r["name"] == "Slither")
        assert slither_status["status"] == "MISSING"

    def test_optional_tool_missing_does_not_fail(self, capsys):
        def fake_which(cmd: str):
            # myth and aderyn missing, everything else present
            if cmd in ("myth", "aderyn"):
                return None
            return f"/usr/bin/{cmd}"

        tool_outputs = {
            "slither": "0.11.5",
            "medusa":  "medusa version 0.1.8",
            "forge":   "forge Version: 1.6.0",
            "solc":    "Version: 0.8.33",
            "go":      "go version go1.21.0",
        }

        def fake_run(cmd, **kwargs):
            binary = cmd[0]
            text = tool_outputs.get(binary, "")
            return MagicMock(stdout=text, stderr="", returncode=0)

        with patch("shutil.which", side_effect=fake_which), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("importlib.metadata.version", return_value="1.0.0"):
            result = doctor.run_doctor()

        assert result["all_core_ok"] is True
        assert result["exit_code"] == 0

    def test_output_contains_tool_names(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            doctor.run_doctor()
        captured = capsys.readouterr().out
        for name in ("Slither", "Mythril", "Medusa", "Aderyn", "Forge", "solc"):
            assert name in captured

    def test_output_contains_summary(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            doctor.run_doctor()
        captured = capsys.readouterr().out
        assert "Summary:" in captured

    def test_tools_list_has_correct_count(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            result = doctor.run_doctor()
        # TOOL_SPECS defines 6 tools
        assert len(result["tools"]) == len(doctor.TOOL_SPECS)

    def test_packages_list_has_expected_entries(self, capsys):
        patches = self._patch_all_found()
        with patches[0], patches[1], patches[2]:
            result = doctor.run_doctor()
        pkg_names = {p["name"] for p in result["packages"]}
        assert "sentence-transformers" in pkg_names
        assert "numpy" in pkg_names

    def test_go_missing_is_optional_not_failure(self, capsys):
        """Go absent (Docker runtime) must yield OPTIONAL status, not MISSING, and not affect exit_code."""
        def fake_which(cmd: str):
            if cmd == "go":
                return None
            return f"/usr/bin/{cmd}"

        tool_outputs = {
            "slither": "0.11.5",
            "myth":    "mythril version 0.24.8",
            "medusa":  "medusa version 0.1.8",
            "aderyn":  "aderyn 0.6.2",
            "forge":   "forge Version: 1.6.0",
            "solc":    "Version: 0.8.33+commit.abc",
        }

        def fake_run(cmd, **kwargs):
            binary = cmd[0]
            if binary == "go":
                raise FileNotFoundError("go not found")
            text = tool_outputs.get(binary, "")
            return MagicMock(stdout=text, stderr="", returncode=0)

        with patch("shutil.which", side_effect=fake_which), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("importlib.metadata.version", return_value="1.0.0"):
            result = doctor.run_doctor()

        assert result["go"]["status"] == "OPTIONAL"
        # Go missing must not push exit_code to 1 (all_core_ok depends only on tool_results)
        assert result["all_core_ok"] is True
        assert result["exit_code"] == 0

    def test_mythril_version_extracted_from_noisy_output(self):
        """Version parser must find version even when traceback precedes the version line."""
        noisy_output = (
            "Traceback (most recent call last):\n"
            "  File '/usr/lib/python3/dist-packages/pkg_resources/__init__.py', line 123\n"
            "    SomeWarning: something deprecated\n"
            "Mythril version 0.24.8\n"
        )
        with patch("shutil.which", return_value="/usr/bin/myth"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=noisy_output, stderr="", returncode=0)
            result = doctor._check_tool(
                "Mythril", "myth", ["version"], r"(\d+\.\d+\.\d+)",
                "0.24.8", "pip install mythril", is_core=False,
            )
        assert result["status"] == "OK"
        assert result["version"] == "0.24.8"

    def test_mythril_traceback_without_version_returns_actionable_error(self):
        bad_output = (
            "Traceback (most recent call last):\n"
            "  File '/usr/local/bin/myth', line 5, in <module>\n"
            "    from mythril.interfaces.cli import main\n"
        )
        with patch("shutil.which", return_value="/usr/bin/myth"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=bad_output, stderr="", returncode=0)
            result = doctor._check_tool(
                "Mythril", "myth", ["version"], r"(\d+\.\d+\.\d+)",
                "0.24.8", "pip install mythril", is_core=False,
            )
        assert result["status"] == "ERROR"
        assert "check runtime deps" in result["notes"]
