"""Plugin architecture for Sentinel Engine.

Supports community-contributed analyzers and heuristic rules via a
simple plugin discovery mechanism. Plugins are Python modules placed
in configured directories that expose a ``register()`` function.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Protocol, runtime_checkable

try:
    from logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Plugin Protocols
# ---------------------------------------------------------------------------

@runtime_checkable
class AnalyzerPlugin(Protocol):
    """Protocol for community analyzer plugins."""
    name: str
    version: str
    
    def analyze(
        self, target: str, config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run analysis on target, return list of finding dicts."""
        ...


@runtime_checkable
class RulePlugin(Protocol):
    """Protocol for custom heuristic rule plugins."""
    
    def get_rules(self) -> list:
        """Return list of HeuristicRule instances."""
        ...


# ---------------------------------------------------------------------------
# Plugin Manager
# ---------------------------------------------------------------------------

class PluginManager:
    """Discovers, registers, and manages plugins."""
    
    def __init__(self) -> None:
        self._analyzers: List[AnalyzerPlugin] = []
        self._rule_plugins: List[RulePlugin] = []
        self._loaded_modules: Dict[str, Any] = {}
    
    def discover_plugins(self, plugin_dirs: List[str]) -> int:
        """Scan directories for plugin modules with a register() function.
        
        Returns the number of plugins successfully loaded.
        """
        count = 0
        for dir_path in plugin_dirs:
            p = Path(dir_path).expanduser().resolve()
            if not p.is_dir():
                logger.debug("Plugin directory does not exist: %s", p)
                continue
            
            for py_file in sorted(p.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                try:
                    module = self._load_module(py_file)
                    if hasattr(module, "register"):
                        module.register(self)
                        count += 1
                        logger.info("Loaded plugin: %s", py_file.name)
                    else:
                        logger.debug(
                            "Skipping %s — no register() function",
                            py_file.name
                        )
                except Exception as exc:
                    logger.warning(
                        "Failed to load plugin %s: %s", py_file.name, exc
                    )
        
        logger.info(
            "Plugin discovery complete: %d plugins loaded "
            "(%d analyzers, %d rule sets)",
            count, len(self._analyzers), len(self._rule_plugins),
        )
        return count
    
    def _load_module(self, path: Path) -> Any:
        """Dynamically load a Python module from a file path."""
        module_name = f"sentinel_plugin_{path.stem}"
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]
        
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec for {path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        self._loaded_modules[module_name] = module
        return module
    
    def register_analyzer(self, plugin: AnalyzerPlugin) -> None:
        """Register an analyzer plugin."""
        if not isinstance(plugin, AnalyzerPlugin):
            raise TypeError(
                f"Expected AnalyzerPlugin protocol, "
                f"got {type(plugin).__name__}"
            )
        self._analyzers.append(plugin)
        logger.info(
            "Registered analyzer plugin: %s v%s",
            plugin.name, plugin.version
        )
    
    def register_rules(self, plugin: RulePlugin) -> None:
        """Register a rule plugin."""
        if not isinstance(plugin, RulePlugin):
            raise TypeError(
                f"Expected RulePlugin protocol, got {type(plugin).__name__}"
            )
        self._rule_plugins.append(plugin)
        logger.info("Registered rule plugin: %s", type(plugin).__name__)
    
    def get_analyzers(self) -> List[AnalyzerPlugin]:
        """Return all registered analyzer plugins."""
        return list(self._analyzers)
    
    def get_rules(self) -> list:
        """Return all rules from registered rule plugins."""
        all_rules = []
        for plugin in self._rule_plugins:
            try:
                rules = plugin.get_rules()
                all_rules.extend(rules)
            except Exception as exc:
                logger.warning("Failed to get rules from plugin: %s", exc)
        return all_rules
    
    def get_analyzer_count(self) -> int:
        return len(self._analyzers)
    
    def get_rule_plugin_count(self) -> int:
        return len(self._rule_plugins)
