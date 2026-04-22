"""Tests for plugin_manager.py."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from plugin_manager import PluginManager, AnalyzerPlugin, RulePlugin


# ---------------------------------------------------------------------------
# Stub plugins for testing
# ---------------------------------------------------------------------------

class GoodAnalyzer:
    name = "TestAnalyzer"
    version = "1.0.0"
    def analyze(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{"finding": "test"}]

class GoodRulePlugin:
    def get_rules(self) -> list:
        return ["rule_a", "rule_b"]

class BrokenRulePlugin:
    def get_rules(self) -> list:
        raise RuntimeError("plugin broken")

class NotAnAnalyzer:
    pass

class NotARulePlugin:
    pass


# ---------------------------------------------------------------------------
# TestPluginManagerBasic
# ---------------------------------------------------------------------------

class TestPluginManagerBasic:
    def test_initial_counts_are_zero(self) -> None:
        pm = PluginManager()
        assert pm.get_analyzer_count() == 0
        assert pm.get_rule_plugin_count() == 0

    def test_get_analyzers_empty(self) -> None:
        pm = PluginManager()
        assert pm.get_analyzers() == []

    def test_get_rules_empty(self) -> None:
        pm = PluginManager()
        assert pm.get_rules() == []

    def test_register_analyzer_increments_count(self) -> None:
        pm = PluginManager()
        pm.register_analyzer(GoodAnalyzer())
        assert pm.get_analyzer_count() == 1

    def test_register_multiple_analyzers(self) -> None:
        pm = PluginManager()
        pm.register_analyzer(GoodAnalyzer())
        pm.register_analyzer(GoodAnalyzer())
        assert pm.get_analyzer_count() == 2

    def test_get_analyzers_returns_copies(self) -> None:
        pm = PluginManager()
        a = GoodAnalyzer()
        pm.register_analyzer(a)
        result = pm.get_analyzers()
        assert a in result
        # Modifying returned list doesn't affect internal state
        result.clear()
        assert pm.get_analyzer_count() == 1

    def test_register_rules_increments_count(self) -> None:
        pm = PluginManager()
        pm.register_rules(GoodRulePlugin())
        assert pm.get_rule_plugin_count() == 1

    def test_get_rules_returns_all_rules(self) -> None:
        pm = PluginManager()
        pm.register_rules(GoodRulePlugin())
        rules = pm.get_rules()
        assert "rule_a" in rules
        assert "rule_b" in rules

    def test_get_rules_multiple_plugins(self) -> None:
        pm = PluginManager()

        class AnotherRules:
            def get_rules(self) -> list:
                return ["rule_c"]

        pm.register_rules(GoodRulePlugin())
        pm.register_rules(AnotherRules())
        rules = pm.get_rules()
        assert len(rules) == 3

    def test_get_rules_skips_broken_plugin(self) -> None:
        pm = PluginManager()
        pm.register_rules(BrokenRulePlugin())
        # Should not raise; broken plugin is logged and skipped
        rules = pm.get_rules()
        assert rules == []


# ---------------------------------------------------------------------------
# TestPluginManagerTypeChecks
# ---------------------------------------------------------------------------

class TestPluginManagerTypeChecks:
    def test_register_analyzer_rejects_non_protocol(self) -> None:
        pm = PluginManager()
        with pytest.raises(TypeError):
            pm.register_analyzer(NotAnAnalyzer())  # type: ignore

    def test_register_rules_rejects_non_protocol(self) -> None:
        pm = PluginManager()
        with pytest.raises(TypeError):
            pm.register_rules(NotARulePlugin())  # type: ignore


# ---------------------------------------------------------------------------
# TestDiscoverPlugins
# ---------------------------------------------------------------------------

class TestDiscoverPlugins:
    def test_discover_nonexistent_directory(self) -> None:
        pm = PluginManager()
        count = pm.discover_plugins(["/nonexistent/path/that/does/not/exist"])
        assert count == 0

    def test_discover_empty_directory(self, tmp_path: Path) -> None:
        pm = PluginManager()
        count = pm.discover_plugins([str(tmp_path)])
        assert count == 0

    def test_discover_valid_plugin_module(self, tmp_path: Path) -> None:
        """A plugin file with register() should be discovered and loaded."""
        plugin_file = tmp_path / "my_plugin.py"
        plugin_file.write_text(
            "def register(manager):\n"
            "    pass\n",
            encoding="utf-8",
        )
        pm = PluginManager()
        count = pm.discover_plugins([str(tmp_path)])
        assert count == 1

    def test_discover_skips_dunder_files(self, tmp_path: Path) -> None:
        """Files starting with _ should be ignored."""
        (tmp_path / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "_private.py").write_text("def register(m): pass", encoding="utf-8")
        pm = PluginManager()
        count = pm.discover_plugins([str(tmp_path)])
        assert count == 0

    def test_discover_skips_files_without_register(self, tmp_path: Path) -> None:
        no_register = tmp_path / "no_register.py"
        no_register.write_text("x = 1\n", encoding="utf-8")
        pm = PluginManager()
        count = pm.discover_plugins([str(tmp_path)])
        assert count == 0

    def test_discover_handles_broken_plugin(self, tmp_path: Path) -> None:
        """Broken plugin (syntax error) should log warning and continue."""
        broken = tmp_path / "broken_plugin.py"
        broken.write_text("this is not valid python!!!\n", encoding="utf-8")
        pm = PluginManager()
        # Should not raise
        count = pm.discover_plugins([str(tmp_path)])
        assert count == 0

    def test_discover_multiple_directories(self, tmp_path: Path) -> None:
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "plugin1.py").write_text("def register(m): pass\n", encoding="utf-8")
        (dir2 / "plugin2.py").write_text("def register(m): pass\n", encoding="utf-8")
        pm = PluginManager()
        count = pm.discover_plugins([str(dir1), str(dir2)])
        assert count == 2

    def test_load_module_cached(self, tmp_path: Path) -> None:
        """Loading the same module twice should return cached instance."""
        py_file = tmp_path / "mymod.py"
        py_file.write_text("x = 42\n", encoding="utf-8")
        pm = PluginManager()
        mod1 = pm._load_module(py_file)
        mod2 = pm._load_module(py_file)
        assert mod1 is mod2
