"""Severity weighting, risk scoring, and pass/fail gating.

Single source of truth replacing three inline copies in webapp/main.py
(results page, dashboard loader, _load_audits_from_results_dir) and the
identical definition in scan_utils.py (SEVERITY_WEIGHTS).
All call sites collapse to two-line imports.

Verified: risk_score_from_counts({CRITICAL:2, HIGH:1, MEDIUM:3}) == 51.7
          (matches the three inline formulas exactly)
          pass_fail_from_counts({CRITICAL:1}) == "FAIL"
          pass_fail_from_counts({HIGH:4})     == "FAIL"
          pass_fail_from_counts({HIGH:2})     == "WARNING"
          pass_fail_from_counts({})           == "PASS"
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical weight mapping (was SEVERITY_WEIGHTS in scan_utils.py and
# anonymous dicts on lines 590-593 and 958-961 of main.py).
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.1,
}

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def normalize_counts(raw: dict[str, int]) -> dict[str, int]:
    """Coerce a severity-count dict to uppercase canonical keys.

    Handles both lower-case keys (from scan_index.json) and upper-case keys
    (from findings_data) so callers don't have to care about storage format.
    """
    result: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for k, v in raw.items():
        upper = k.upper()
        if upper in result:
            result[upper] = result[upper] + int(v or 0)
    return result


def risk_score_from_counts(severity_counts: dict[str, int]) -> float:
    """Return a 0–100 risk score from a severity count dict.

    Uses SEVERITY_WEIGHTS; normalises keys before calculation so either
    case form works.  Returns 0.0 when no findings exist.
    """
    counts = normalize_counts(severity_counts)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    total_weight = sum(
        SEVERITY_WEIGHTS.get(k, 0.0) * v for k, v in counts.items()
    )
    max_weight = total * SEVERITY_WEIGHTS["CRITICAL"]
    return round(min(100.0, (total_weight / max(max_weight, 1.0)) * 100), 1)


def risk_score_from_findings(findings: list[dict]) -> float:
    """Return risk score directly from a list of finding dicts."""
    total = len(findings)
    if total == 0:
        return 0.0
    total_weight = sum(
        SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 0.0) for f in findings
    )
    max_weight = total * SEVERITY_WEIGHTS["CRITICAL"]
    return round(min(100.0, (total_weight / max(max_weight, 1.0)) * 100), 1)


def pass_fail_from_counts(severity_counts: dict[str, int]) -> str:
    """Return ``"PASS"``, ``"WARNING"``, or ``"FAIL"`` for a count dict.

    Thresholds (unchanged from original inline logic in results()):
      - FAIL    if any CRITICAL, or HIGH > 3
      - WARNING if any HIGH
      - PASS    otherwise
    """
    counts = normalize_counts(severity_counts)
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    if critical > 0 or high > 3:
        return "FAIL"
    if high > 0:
        return "WARNING"
    return "PASS"
