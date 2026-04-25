# Contributing to Counterscarp Engine

Thank you for your interest in contributing to Counterscarp Engine! This guide will help you get started with adding new features, fixing bugs, and improving the codebase.

> **Website:** [counterscarp.io](https://counterscarp.io)  
> **Issues:** Report issues via email: contact@counterscarp.io

---

## Table of Contents

- [Development Setup](#development-setup)
- [How to Add a New Heuristic Rule](#how-to-add-a-new-heuristic-rule)
- [How to Integrate a Custom Static Analyzer](#how-to-integrate-a-custom-static-analyzer)
- [How to Write Tests](#how-to-write-tests)
- [Error Handling Conventions](#error-handling-conventions)
- [Code Style](#code-style)
- [Environment Variables](#environment-variables)

---

## Development Setup

### Prerequisites

- **Python 3.10+** (required)
- **pip** for dependency management
- **Git** for version control

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/RunTimeAdmin/counterscarp-engine.git
cd counterscarp-engine

# 2. Create a virtual environment (recommended)
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

# 3. Install dependencies (using pyproject.toml)
pip install -e ".[dev]"

# 4. Verify installation
counterscarp-engine --help
# Or: python orchestrator.py --help
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_heuristic_scanner.py

# Run with verbose output
pytest -v
```

---

## How to Add a New Heuristic Rule

Heuristic rules are defined in [`heuristic_scanner.py`](heuristic_scanner.py). Each rule detects a specific vulnerability pattern using regular expressions.

### Understanding the `HeuristicRule` Dataclass

```python
@dataclass
class HeuristicRule:
    """Represents a heuristic detection rule.

    Attributes:
        id: Unique identifier for this rule (UPPER_SNAKE_CASE).
        description: Human-readable description of what this rule detects.
        severity: Default severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        pattern: Compiled regex pattern to match against code.
        hint: Remediation hint for developers.
    """
    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    hint: str
```

### Step-by-Step Guide

1. **Open `heuristic_scanner.py`** and locate the `RULES` list (around line 77).

2. **Add your new rule** to the list:

```python
HeuristicRule(
    id="MY_NEW_RULE",
    description="Brief description of the vulnerability",
    severity="HIGH",  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    pattern=re.compile(r"your_regex_pattern_here"),
    hint="Provide clear remediation guidance for developers..."
),
```

3. **Follow these guidelines:**
   - Use `UPPER_SNAKE_CASE` for rule IDs
   - Severity should reflect real-world exploit impact
   - Patterns should be specific enough to avoid false positives
   - Hints should include actionable fix suggestions

### Example Rule Definitions

**Simple Pattern Match:**
```python
HeuristicRule(
    id="TX_ORIGIN_USAGE",
    description="Use of tx.origin (dangerous for auth checks)",
    severity="HIGH",
    pattern=re.compile(r"tx\.origin"),
    hint="Avoid tx.origin for authorization; use msg.sender and proper role-based access control.",
),
```

**Complex Pattern with Lookahead:**
```python
HeuristicRule(
    id="ORACLE_STALENESS_CHECK",
    description="Chainlink oracle without staleness/validity check",
    severity="CRITICAL",
    pattern=re.compile(r"(latestAnswer|latestRoundData)\(\)(?!.*require.*updatedAt|.*block\.timestamp)"),
    hint="CRITICAL: Check updatedAt timestamp and answeredInRound to prevent stale price attacks.",
),
```

### Context Filtering (Comment/String Awareness)

The scanner automatically filters out matches that occur in:
- Single-line comments (`//`)
- Multi-line comments (`/* */`)
- String literals (`"..."` or `'...'`)

This is handled by the [`is_in_code_context()`](heuristic_scanner.py#L253) and [`is_in_multiline_comment()`](heuristic_scanner.py#L300) functions. You don't need to modify these unless you're adding new context types.

### Testing Your Rule

```python
# Test the rule manually
python heuristic_scanner.py /path/to/test/contracts --config counterscarp-pr.toml

# Or write a unit test
def test_my_new_rule():
    test_code = "// vulnerable code with tx.origin"
    findings = scan_file("test.sol", config=None)
    assert any(f.rule_id == "MY_NEW_RULE" for f in findings)
```

---

## How to Integrate a Custom Static Analyzer

You can integrate external static analysis tools by following the wrapper pattern used by existing analyzers like [`aderyn_wrapper.py`](aderyn_wrapper.py).

### Pattern to Follow

1. **Create a new wrapper file** (e.g., `my_analyzer_wrapper.py`):

```python
#!/usr/bin/env python3
"""Wrapper for My Custom Analyzer."""

from __future__ import annotations

import subprocess
import json
from typing import Dict, Any, List

from logger import get_logger
from exceptions import (
    CounterscarfAnalysisError,
    CounterscarfToolNotFoundError,
    CounterscarfTimeoutError,
)

logger = get_logger(__name__)


def check_tool_installed() -> bool:
    """Check if the analyzer is available."""
    try:
        result = subprocess.run(
            ["my-analyzer", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def run_my_analyzer(project_root: str) -> Dict[str, Any]:
    """Run the analyzer and return structured results."""
    if not check_tool_installed():
        raise CounterscarfToolNotFoundError(
            "my-analyzer not found",
            details={"tool": "my-analyzer", "install_cmd": "pip install my-analyzer"}
        )
    
    cmd = ["my-analyzer", project_root, "--output", "json"]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired as e:
        raise CounterscarfTimeoutError(
            "Analysis timed out",
            details={"operation": "my_analyzer", "timeout_seconds": 120}
        ) from e
    except Exception as e:
        raise CounterscarfAnalysisError(
            "Analysis failed",
            details={"error": str(e)}
        ) from e
```

2. **Add graceful import fallback in `orchestrator.py`**:

```python
# In orchestrator.py, add near other optional imports (around line 27)

try:
    import my_analyzer_wrapper
    logger.debug("My analyzer wrapper imported successfully")
except ImportError as e:
    logger.info(f"My analyzer not available: {e}")
    my_analyzer_wrapper = None
```

3. **Integrate into the analysis pipeline**:

```python
# In orchestrator.py main(), add a new phase:

# [PHASE X] My Custom Analyzer
if args.my_analyzer and os.path.isdir(args.target):
    print("\n>>> Running My Custom Analyzer...")
    if my_analyzer_wrapper is None:
        print("[!] My analyzer not available.")
    else:
        try:
            my_results = my_analyzer_wrapper.run_my_analyzer(args.target)
        except Exception:
            print("[!] My analyzer failed; continuing without results.")
            my_results = {"error": "Analysis failed"}
```

### Expected Output Format

Your wrapper should return a dictionary with this structure:

```python
{
    "findings": [
        {
            "rule_id": "RULE_NAME",
            "severity": "CRITICAL",  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            "title": "Short description",
            "description": "Detailed explanation",
            "file": "path/to/file.sol",
            "line_no": 42,
            "code_snippet": "optional code excerpt"
        }
    ],
    "summary": {
        "total": 1,
        "critical": 1,
        "high": 0,
        # ... etc
    }
}
```

---

## How to Write Tests

### Test Directory Structure

```
counterscarp-engine/
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures
│   ├── test_access_matrix.py
│   ├── test_config_loader.py
│   ├── test_exceptions.py
│   ├── test_heuristic_scanner.py
│   ├── test_intent_check.py
│   ├── test_orchestrator.py
│   ├── test_red_team_scan.py
│   ├── test_report_generator.py
│   ├── test_supply_chain_check.py
│   └── test_upgrade_diff.py
└── test_fixtures/               # Optional: test contract files
    ├── vulnerable_contract.sol
    └── safe_contract.sol
```

### Using Shared Fixtures from `conftest.py`

Create a `tests/conftest.py` file with common fixtures:

```python
"""Shared test fixtures for Counterscarp Engine."""

import pytest
import tempfile
import os


@pytest.fixture
def temp_sol_file():
    """Create a temporary Solidity file for testing."""
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.sol',
        delete=False
    ) as f:
        f.write("""
pragma solidity ^0.8.0;

contract Test {
    function vulnerable() public {
        // Code with known vulnerability
        tx.origin.call{value: 1 ether}("");
    }
}
""")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    os.unlink(temp_path)


@pytest.fixture
def mock_config():
    """Return a mock configuration object."""
    from unittest.mock import MagicMock
    config = MagicMock()
    config.heuristics.enabled = True
    config.heuristics.disabled_rules = []
    config.heuristics.get_rule_severity.return_value = "HIGH"
    config.is_finding_suppressed.return_value = None
    return config
```

### Mocking Guidelines for External Tools

When testing code that calls external tools (Slither, Aderyn, etc.), use mocking:

```python
import pytest
from unittest.mock import patch, MagicMock


def test_slither_wrapper_mocked():
    """Test slither wrapper with mocked subprocess."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"results": {"detectors": []}}'
    mock_result.stderr = ''
    
    with patch('subprocess.run', return_value=mock_result):
        from red_team_scan import run_slither
        results = run_slither('./test_contracts')
        assert results == []


def test_aderyn_not_installed():
    """Test behavior when Aderyn is not installed."""
    with patch('subprocess.run', side_effect=FileNotFoundError()):
        from aderyn_wrapper import check_aderyn_installed
        assert check_aderyn_installed() is False
```

### Testing Heuristic Rules

```python
def test_tx_origin_detection(temp_sol_file, mock_config):
    """Test that tx.origin usage is detected."""
    from heuristic_scanner import scan_file
    
    findings = scan_file(temp_sol_file, mock_config)
    
    tx_origin_findings = [f for f in findings if f.rule_id == "TX_ORIGIN_USAGE"]
    assert len(tx_origin_findings) > 0
    assert tx_origin_findings[0].severity == "HIGH"
```

---

## Error Handling Conventions

### Custom Exception Hierarchy

All exceptions are defined in [`exceptions.py`](exceptions.py):

```
CounterscarfError (base)
├── CounterscarfConfigError      # Configuration issues
├── CounterscarfAnalysisError    # Analyzer failures
├── CounterscarfAPIError         # External API failures
├── CounterscarfReportError      # Report generation failures
├── CounterscarfToolNotFoundError # Missing external tools
├── CounterscarfValidationError  # Input validation failures
└── CounterscarfTimeoutError     # Operation timeouts
```

### When to Use Each Exception Type

| Exception | Use When | Example |
|-----------|----------|---------|
| `CounterscarfConfigError` | TOML syntax error, invalid config value | Missing `[engine]` section |
| `CounterscarfAnalysisError` | Slither/Aderyn/Mythril fails | Compilation error, timeout |
| `CounterscarfAPIError` | OSV.dev or threat intel API fails | 500 error from API |
| `CounterscarfReportError` | Can't write report file | Permission denied on output dir |
| `CounterscarfToolNotFoundError` | External tool not installed | Slither not in PATH |
| `CounterscarfValidationError` | User input is invalid | Invalid contract address format |
| `CounterscarfTimeoutError` | Operation exceeds time limit | Mythril analysis > 5 minutes |

### API Integration with `http_utils.py`

When adding new API integrations (threat intelligence, external services), use the resilient HTTP utilities:

```python
from http_utils import resilient_get, resilient_post

# Automatic retry with exponential backoff
response = resilient_get(
    "https://api.example.com/data",
    timeout=30,
    max_retries=3
)

# Rate-limited POST requests
response = resilient_post(
    "https://api.example.com/submit",
    json={"key": "value"},
    rate_limit=5  # requests per second
)
```

Features:
- **Exponential backoff** with jitter for failed requests
- **Rate limiting** to prevent API quota exhaustion
- **Automatic retry** on 5xx errors and timeouts
- **Respects `Retry-After` headers** for rate limiting

### Logging Conventions

Use the centralized logger from [`logger.py`](logger.py):

```python
from logger import get_logger

logger = get_logger(__name__)

# Different log levels:
logger.debug("Detailed debugging info")      # Development only
logger.info("General operational info")       # Normal operation
logger.warning("Potential issue detected")    # Non-critical problem
logger.error("Error occurred")                # Something failed
logger.critical("Critical failure")           # May crash the program
```

**Best Practices:**
- Use `debug` for detailed tracing (regex matches, internal state)
- Use `info` for milestones ("Scan started", "Report generated")
- Use `warning` for recoverable issues ("Tool not found, skipping")
- Use `error` for failures that affect output quality
- Use `critical` for failures that prevent any output

### Exception Chaining

Always chain exceptions to preserve context:

```python
from exceptions import CounterscarfConfigError

try:
    load_config(path)
except Exception as e:
    raise CounterscarfConfigError(
        "Failed to load configuration",
        details={"path": path, "error": str(e)}
    ) from e
```

---

## Code Style

### Type Hints

**All public APIs must have type hints:**

```python
from typing import List, Dict, Optional, Any

def scan_target(
    target: str,
    config: Optional[CounterscarfConfig] = None
) -> List[HeuristicFinding]:
    """Scan a target file or directory.
    
    Args:
        target: Path to .sol file or directory.
        config: Optional configuration object.
        
    Returns:
        List of heuristic findings.
    """
    ...
```

### Google-Style Docstrings

Use Google-style docstrings for all functions and classes:

```python
def calculate_risk_score(findings: List[Finding]) -> float:
    """Calculate overall risk score (0-100) based on finding severity.

    Formula: weighted_sum / max_possible_weight

    Args:
        findings: List of findings to calculate score from.

    Returns:
        Risk score between 0 and 100.

    Example:
        >>> findings = [Finding(severity="CRITICAL", ...)]
        >>> score = calculate_risk_score(findings)
        >>> print(f"Risk: {score}/100")
    """
```

### `from __future__ import annotations`

**Every Python file must include this import at the top:**

```python
#!/usr/bin/env python3
"""Module docstring."""

from __future__ import annotations

import os
import re
from typing import List, Optional

# Your code here
```

This enables:
- Postponed evaluation of annotations (PEP 563)
- Use of forward references without quotes
- Better performance for type checking

---

## Environment Variables

The following environment variables are supported:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `COUNTERSCARP_LOG_LEVEL` | Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL | INFO | No |
| `COUNTERSCARP_LOG_FORMAT` | Output format: "text" or "json" | text | No |
| `COUNTERSCARP_LOG_FILE` | Path to log file (optional) | (none) | No |
| `OPENAI_API_KEY` | OpenAI API key for exploit generation | (none) | For AI features |

### Usage Examples

```bash
# Debug logging to file
export COUNTERSCARP_LOG_LEVEL=DEBUG
export COUNTERSCARP_LOG_FILE=/var/log/counterscarp.log
python orchestrator.py --target ./contracts

# JSON format for structured logging
export COUNTERSCARP_LOG_FORMAT=json
python orchestrator.py --target ./contracts 2>&1 | jq

# OpenAI for exploit generation
export OPENAI_API_KEY="sk-..."
python exploit_generator.py --finding-json findings.json
```

---

## Submitting Contributions

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the guidelines above
3. **Add tests** for new functionality
4. **Run the test suite** to ensure nothing is broken
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

### Pull Request Checklist

- [ ] Code follows the style guidelines
- [ ] Type hints on all public APIs
- [ ] Google-style docstrings added/updated
- [ ] `from __future__ import annotations` at top of file
- [ ] Tests added for new functionality
- [ ] All tests pass (`pytest`)
- [ ] Documentation updated (README, CONTRIBUTING, etc.)
- [ ] No hardcoded paths or credentials

---

## Questions?

- Open an issue on GitHub
- Visit [counterscarp.io](https://counterscarp.io)
- Contact: [@defiauditccie](https://twitter.com/defiauditccie)

Thank you for contributing to Counterscarp Engine!
