from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Compiled regex for inline suppression pragmas
SUPPRESS_PATTERN: re.Pattern[str]

# Rule categories: groups rule IDs by security domain
RULE_CATEGORIES: Dict[str, List[str]]

# Built-in heuristic rules list
RULES: List[HeuristicRule]

# Alias for RULES (used by webapp and coverage helpers)
HEURISTIC_RULES: List[HeuristicRule]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HeuristicFinding:
    """Represents a heuristic scan finding."""
    rule_id: str
    severity: str
    message: str
    file: str
    line_no: int
    line_text: str
    suppressed: bool
    suppression_reason: str
    confidence: int
    similar_locations: List[str]
    duplicate_count: int


@dataclass
class HeuristicRule:
    """Represents a heuristic detection rule."""
    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    hint: str
    confidence: int
    refine: Optional[Callable[["HeuristicFinding", List[str], int], bool]]


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def get_scan_coverage() -> Dict[str, Any]:
    """Return scan coverage metadata for the heuristic scanner."""
    ...


def get_all_rules(plugin_mgr: Optional[Any] = ...) -> List[HeuristicRule]:
    """Return built-in rules plus any plugin-contributed rules."""
    ...


def is_in_code_context(line: str, match_start: int) -> bool:
    """Check if a regex match is in actual code vs. a comment or string literal."""
    ...


def is_in_multiline_comment(
    lines: List[str], line_idx: int, match_start: int
) -> bool:
    """Check if a position is inside a multi-line comment (/* */).

    .. deprecated:: use _build_comment_map() + comment_map[line_idx] instead.
    """
    ...


def should_exclude(
    file_path: str, exclude_patterns: List[str], base_dir: str = ...
) -> bool:
    """Check if a file path matches any exclusion glob pattern."""
    ...


def scan_file(
    path: str,
    config: Optional[Any] = ...,
    plugin_mgr: Optional[Any] = ...,
) -> List[HeuristicFinding]:
    """Scan a single .sol file and return heuristic findings."""
    ...


def scan_target(
    target: str,
    config: Optional[Any] = ...,
    plugin_mgr: Optional[Any] = ...,
    exclude_paths: Optional[List[str]] = ...,
) -> List[HeuristicFinding]:
    """Scan a .sol file or all .sol files under a directory."""
    ...


def print_report(
    findings: List[HeuristicFinding], show_suppressed: bool = ...
) -> None:
    """Print a formatted report of heuristic findings."""
    ...


def main() -> None:
    """Main entry point for the heuristic scanner CLI."""
    ...
