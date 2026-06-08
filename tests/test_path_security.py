"""Tests for path_security helpers."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from exceptions import CounterscarpValidationError
from path_security import (
    sanitize_cli_path,
    sanitize_project_slug,
    sanitize_scan_target,
    validate_git_branch_name,
    validate_git_since_date,
    validate_solidity_identifier,
    write_private_file,
)


class TestSanitizeProjectSlug:
    def test_strips_unsafe_characters(self):
        assert sanitize_project_slug("my/project") == "my_project"

    def test_rejects_dot_only_slug(self):
        assert sanitize_project_slug("..") == "scan"

    def test_empty_defaults_to_scan(self):
        assert sanitize_project_slug("") == "scan"
        assert sanitize_project_slug("___") == "scan"


class TestSanitizeScanTarget:
    def test_accepts_directory_target(self, tmp_path: Path):
        project = tmp_path / "foundry_project"
        project.mkdir()
        resolved = sanitize_scan_target(str(project))
        assert resolved.is_dir()

    def test_accepts_sol_file(self, tmp_path: Path):
        sol_file = tmp_path / "Token.sol"
        sol_file.write_text("pragma solidity ^0.8.0;", encoding="utf-8")
        resolved = sanitize_scan_target(str(sol_file))
        assert resolved.is_file()
        assert resolved.suffix == ".sol"

    def test_rejects_traversal(self):
        with pytest.raises(CounterscarpValidationError):
            sanitize_scan_target("../outside")

    def test_rejects_missing_target(self, tmp_path: Path):
        missing = tmp_path / "missing.sol"
        with pytest.raises(CounterscarpValidationError):
            sanitize_scan_target(str(missing))


class TestSanitizeCliPathTraversal:
    def test_rejects_parent_segments(self, tmp_path: Path):
        nested = tmp_path / "nested"
        nested.mkdir()
        with pytest.raises(CounterscarpValidationError):
            sanitize_cli_path(str(nested / ".." / "nested"), must_exist=True, expect_file=False)

    def test_confined_to_rejects_escape(self, tmp_path: Path):
        root = tmp_path / "scan_root"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        with pytest.raises(CounterscarpValidationError):
            sanitize_cli_path(str(outside), confined_to=root)


class TestInputValidators:
    def test_validate_solidity_identifier(self):
        assert validate_solidity_identifier("InvariantTest") == "InvariantTest"
        with pytest.raises(CounterscarpValidationError):
            validate_solidity_identifier("../../Token")

    def test_validate_git_branch_name(self):
        assert validate_git_branch_name("main") == "main"
        with pytest.raises(CounterscarpValidationError):
            validate_git_branch_name("--exec=evil")

    def test_validate_git_since_date(self):
        assert validate_git_since_date("2024-01-01") == "2024-01-01"
        with pytest.raises(CounterscarpValidationError):
            validate_git_since_date("not-a-date")


class TestWritePrivateFile:
    def test_sets_owner_only_permissions(self, tmp_path: Path):
        target = tmp_path / "secrets.env"
        write_private_file(target, "OPENAI_API_KEY=abc\n")
        assert target.read_text(encoding="utf-8") == "OPENAI_API_KEY=abc\n"
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(target).st_mode)
            assert mode == 0o600
