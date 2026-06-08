"""Tests for path_security helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from exceptions import CounterscarpValidationError
from path_security import (
    sanitize_cli_path,
    sanitize_project_slug,
    sanitize_scan_target,
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
