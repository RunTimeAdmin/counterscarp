"""Single source of truth for vulnerability severity ordering.

Replaces the six independent ``severity_order`` dicts scattered across:
  orchestrator.py, heuristic_scanner.py, report_generator.py,
  rag_engine.py, history_scanner.py, exploit_generator.py,
  scan_utils.py
"""

from __future__ import annotations

from enum import IntEnum
from typing import Iterable


class Severity(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    @classmethod
    def parse(cls, value: str | None, default: "Severity | None" = None) -> "Severity":
        """Parse a severity string, returning *default* (or INFO) on failure."""
        if value is None:
            return default if default is not None else cls.INFO
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return default if default is not None else cls.INFO

    @property
    def label(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name


#: Tuple of all severities in priority order (critical first).
SEVERITY_ORDER: tuple[Severity, ...] = tuple(Severity)

#: String labels in priority order — for ordered-dict construction and display.
SEVERITY_LABELS: tuple[str, ...] = tuple(s.name for s in Severity)

#: Legacy mapping ``"CRITICAL" -> 0`` for callers not yet migrated to IntEnum.
SEVERITY_RANK: dict[str, int] = {s.name: s.value for s in Severity}

#: Empty severity count template keyed by label string.
EMPTY_SEVERITY_COUNTS: dict[str, int] = {s.name: 0 for s in Severity}


def severity_key(finding: dict) -> int:
    """Sort key for a finding dict — lower value = higher priority."""
    return Severity.parse(finding.get("severity")).value


def sort_findings(findings: list[dict]) -> list[dict]:
    """Return *findings* sorted critical-first.

    Replaces the six local sorted() calls that each define their own
    ``severity_order`` dict inline.
    """
    return sorted(findings, key=severity_key)


def sort_typed_findings(findings: list, sev_attr: str = "severity") -> list:
    """Sort a list of typed Finding objects (any object with a severity attribute)."""
    return sorted(findings, key=lambda f: Severity.parse(getattr(f, sev_attr, None)).value)


def ordered_counts(counts: dict[str, int]) -> dict[str, int]:
    """Return a severity-count dict with keys in canonical order (critical first)."""
    return {label: counts.get(label, 0) for label in SEVERITY_LABELS}
