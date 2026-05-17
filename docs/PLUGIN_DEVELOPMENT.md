# Plugin Development Guide

## Table of Contents

- [Plugin Architecture Overview](#plugin-architecture-overview)
- [Plugin Protocols](#plugin-protocols)
  - [AnalyzerPlugin Protocol](#analyzerplugin-protocol)
  - [RulePlugin Protocol](#ruleplugin-protocol)
- [Creating Your First Plugin](#creating-your-first-plugin)
- [Plugin Registration](#plugin-registration)
- [Testing Plugins](#testing-plugins)
- [Example: Custom Rule Plugin](#example-custom-rule-plugin)
- [Example: Custom Analyzer Plugin](#example-custom-analyzer-plugin)

---

## Plugin Architecture Overview

Counterscarp Engine supports community-contributed analyzers and heuristic rules through a simple plugin discovery mechanism. Plugins are Python modules placed in configured directories that expose a `register()` function.

### How It Works

1. The `PluginManager` scans configured directories for `.py` files
2. Each module with a `register()` function is loaded
3. The `register()` function receives the `PluginManager` instance
4. Plugins call `manager.register_analyzer()` or `manager.register_rules()` to register themselves
5. The orchestrator runs analyzer plugins during the analysis pipeline
6. Rule plugins extend the heuristic scanner with additional patterns

### Directory Structure

```
.scarpshield/
└── plugins/
    ├── my_analyzer.py      # Custom analyzer plugin
    ├── my_rules.py         # Custom rule plugin
    └── __init__.py         # Optional (plugins work without it)
```

**Note:** Files starting with `_` are skipped during discovery.

---

## Plugin Protocols

### AnalyzerPlugin Protocol

Analyzer plugins run custom analysis on target files and return findings.

```python
from typing import Any, Dict, List, Protocol, runtime_checkable

@runtime_checkable
class AnalyzerPlugin(Protocol):
    name: str
    version: str
    
    def analyze(
        self, target: str, config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run analysis on target, return list of finding dicts."""
        ...
```

**Required attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | str | Unique plugin identifier |
| `version` | str | Plugin version string |

**Required method:**

| Method | Returns | Description |
|--------|---------|-------------|
| `analyze(target, config)` | `List[Dict[str, Any]]` | Run analysis, return findings |

**Finding dict format:**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `rule_id` | str | Yes | Unique rule identifier |
| `severity` | str | Yes | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `description` | str | Yes | Human-readable finding description |
| `file` | str | No | Path to the file |
| `line_no` | int | No | Line number |
| `code_snippet` | str | No | Relevant code snippet |

---

### RulePlugin Protocol

Rule plugins extend the heuristic scanner with additional pattern-matching rules.

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class RulePlugin(Protocol):
    
    def get_rules(self) -> list:
        """Return list of HeuristicRule instances."""
        ...
```

**Required method:**

| Method | Returns | Description |
|--------|---------|-------------|
| `get_rules()` | `list[HeuristicRule]` | Return HeuristicRule instances |

Each `HeuristicRule` has:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | str | Unique rule ID (e.g., `"CUSTOM_GAS_GRIEFING"`) |
| `description` | str | Human-readable description |
| `severity` | str | Default severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| `pattern` | `re.Pattern[str]` | Compiled regex pattern |
| `hint` | str | Remediation hint |

---

## Creating Your First Plugin

### Step 1: Create the Plugin Directory

```bash
mkdir -p .scarpshield/plugins
```

### Step 2: Write the Plugin Module

Create `.scarpshield/plugins/my_first_plugin.py`:

```python
"""My first Counterscarp Engine plugin."""
import re
from typing import Any, Dict, List


class MyAnalyzer:
    """Detects custom patterns in Solidity code."""
    
    name = "my-analyzer"
    version = "1.0.0"
    
    def analyze(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan target for custom patterns."""
        findings = []
        
        # Your analysis logic here
        # ...
        
        return findings


def register(manager):
    """Entry point for plugin registration."""
    manager.register_analyzer(MyAnalyzer())
```

### Step 3: Configure the Plugin Directory

In `scarpshield.toml` (or legacy `counterscarp.toml`):

```toml
[plugins]
enabled = true
dirs = [".scarpshield/plugins"]
```

### Step 4: Run with Plugins

```bash
counterscarp --target ./contracts --config scarpshield.toml
```

The orchestrator will log plugin discovery:

```
[*] Plugins loaded: 1 (1 analyzers, 0 rule sets)
```

---

## Plugin Registration

Every plugin must define a top-level `register()` function that receives the `PluginManager` instance:

```python
def register(manager):
    """Called by PluginManager during discovery."""
    manager.register_analyzer(my_analyzer_instance)
    # or
    manager.register_rules(my_rule_plugin_instance)
```

### Registration Methods

| Method | Parameter | Description |
|--------|-----------|-------------|
| `manager.register_analyzer(plugin)` | `AnalyzerPlugin` | Register an analyzer plugin |
| `manager.register_rules(plugin)` | `RulePlugin` | Register a rule plugin |

### Type Checking

The `PluginManager` validates that plugins implement the correct protocol using `isinstance()` checks. If a plugin doesn't match the expected protocol, a `TypeError` is raised:

```python
# This will raise TypeError
manager.register_analyzer("not a plugin")
# TypeError: Expected AnalyzerPlugin protocol, got str
```

---

## Testing Plugins

### Unit Testing

```python
"""Test for my plugin."""
import tempfile
import os
from my_plugin import MyAnalyzer


def test_analyzer_finds_pattern():
    analyzer = MyAnalyzer()
    
    # Create a temp file with the pattern to detect
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write('contract Vulnerable { function bad() public { } }')
        temp_path = f.name
    
    try:
        findings = analyzer.analyze(temp_path, {})
        assert len(findings) > 0
        assert findings[0]['severity'] == 'HIGH'
    finally:
        os.unlink(temp_path)


def test_analyzer_no_false_positives():
    analyzer = MyAnalyzer()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write('contract Safe { function good() internal { } }')
        temp_path = f.name
    
    try:
        findings = analyzer.analyze(temp_path, {})
        assert len(findings) == 0
    finally:
        os.unlink(temp_path)
```

### Integration Testing with PluginManager

```python
"""Integration test with PluginManager."""
from plugin_manager import PluginManager


def test_plugin_discovery():
    manager = PluginManager()
    count = manager.discover_plugins([".scarpshield/plugins"])
    assert count > 0
    assert manager.get_analyzer_count() >= 1
```

---

## Example: Custom Rule Plugin

This plugin adds a rule to detect gas griefing patterns in Solidity:

```python
"""Custom rule plugin: Gas griefing detection."""
import re
from heuristic_scanner import HeuristicRule


class GasGriefingRules:
    """Detects gas griefing vulnerabilities."""
    
    def get_rules(self) -> list:
        return [
            HeuristicRule(
                id="UNBOUNDED_LOOP",
                description="Unbounded loop that can be gas-griefed",
                severity="HIGH",
                pattern=re.compile(r"for\s*\(\s*uint\s+i\s*=\s*0\s*;\s*i\s*<\s*\w+\.length"),
                hint="Use pagination or limit array length to prevent gas griefing attacks.",
            ),
            HeuristicRule(
                id="PAYABLE_FALLBACK_NO_RECEIVE",
                description="Fallback function without receive (ETH may be stuck)",
                severity="MEDIUM",
                pattern=re.compile(r"fallback\s*\(\s*\)\s*external\s+payable"),
                hint="Add a receive() function to handle plain ETH transfers.",
            ),
        ]


def register(manager):
    """Register gas griefing rule plugin."""
    manager.register_rules(GasGriefingRules())
```

Save as `.scarpshield/plugins/gas_griefing_rules.py`.

---

## Example: Custom Analyzer Plugin

This plugin detects TODO/FIXME comments that may indicate incomplete security checks:

```python
"""Custom analyzer plugin: Security TODO scanner."""
import os
import re
from typing import Any, Dict, List


class SecurityTodoScanner:
    """Scans for security-related TODO/FIXME comments that may indicate
    incomplete security checks or known issues."""
    
    name = "security-todo-scanner"
    version = "1.0.0"
    
    # Patterns that suggest security concerns
    SECURITY_KEYWORDS = [
        r"sec(?:urity)?",
        r"auth(?:orization)?",
        r"access\s*control",
        r"reentr(?:ancy)?",
        r"overflow",
        r"underflow",
        r"valid(?:ation|ate)?",
        r"check",
        r"verify",
        r"sanitiz",
    ]
    
    def __init__(self):
        self._pattern = re.compile(
            r"(TODO|FIXME|HACK|XXX|BUG)[\s:]+.*("
            + "|".join(self.SECURITY_KEYWORDS)
            + ")",
            re.IGNORECASE,
        )
    
    def analyze(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan files for security-related TODO/FIXME comments."""
        findings = []
        
        files_to_scan = self._collect_files(target)
        
        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, start=1):
                        match = self._pattern.search(line)
                        if match:
                            findings.append({
                                "rule_id": "SECURITY_TODO",
                                "severity": "LOW",
                                "description": (
                                    f"Security-related {match.group(1)} comment found: "
                                    f"may indicate incomplete security check"
                                ),
                                "file": file_path,
                                "line_no": line_no,
                                "code_snippet": line.strip(),
                            })
            except OSError:
                continue
        
        return findings
    
    def _collect_files(self, target: str) -> list:
        """Collect .sol files from target path."""
        if os.path.isfile(target):
            return [target] if target.endswith(".sol") else []
        
        files = []
        for root, _, filenames in os.walk(target):
            for name in filenames:
                if name.endswith(".sol"):
                    files.append(os.path.join(root, name))
        return files


def register(manager):
    """Register security TODO scanner plugin."""
    manager.register_analyzer(SecurityTodoScanner())
```

Save as `.scarpshield/plugins/security_todo_scanner.py`.

---

*Counterscarp Security Engine &bull; counterscarp.io*
