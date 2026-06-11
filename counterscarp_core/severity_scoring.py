"""Risk-scoring weights and audit-summary mapping helpers.

This module extends ``counterscarp_core.severity`` (which owns ordering) with
the *weighting* and *case-mapping* logic that is currently duplicated across:

  - webapp/scan_utils.py        (SEVERITY_WEIGHTS, summarize_findings_data)
  - webapp/main.py              (two inline ``severity_weights`` literals,
                                 three inline lower<->upper mapping blocks,
                                 risk_score recomputation in results())
  - orchestrator.py             (_compute_risk_metrics)

Consolidating here means a weight change (e.g. bumping HIGH from 5.0 to 6.0)
happens in exactly one place instead of four, and the lower/upper severity-key
translation stops being hand-written at every call site.

NOTE: ``SEVERITY_WEIGHTS`` is intentionally kept numerically identical to the
existing ``webapp/scan_utils.SEVERITY_WEIGHTS`` so behaviour is unchanged.
``scan_utils`` should import from here rather than redefining the dict.
"""

from __future__ import annotations

from typing import Any, Mapping

from counterscarp_core.severity import Severity, SEVERITY_LABELS

#: Canonical risk-scoring weights. Single source of truth.
#: Keys are UPPERCASE labels to match Severity.name.
SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL.name: 10.0,
    Severity.HIGH.name: 5.0,
    Severity.MEDIUM.name: 2.0,
    Severity.LOW.name: 0.5,
    Severity.INFO.name: 0.1,
}


def empty_counts(*, lowercase: bool = False) -> dict[str, int]:
    """Return a zeroed severity-count dict in canonical order.

    Args:
        lowercase: if True keys are ``'critical'..'info'``; else uppercase.
    """
    labels = SEVERITY_LABELS
    if lowercase:
        return {label.lower(): 0 for label in labels}
    return {label: 0 for label in labels}


def normalize_counts(
    raw: Mapping[str, Any] | None,
    *,
    to_upper: bool = True,
) -> dict[str, int]:
    """Translate a severity-count dict between lower/upper keyed forms.

    Replaces the hand-written blocks like::

        {
            "CRITICAL": raw_sev.get("critical", 0),
            "HIGH": raw_sev.get("high", 0),
            ...
        }

    that appear three times in webapp/main.py. Accepts either casing as input
    and emits the requested casing, defaulting any missing severity to 0.

    Args:
        raw: source counts keyed by severity label in any case (may be None).
        to_upper: emit UPPERCASE keys when True, lowercase when False.
    """
    raw = raw or {}
    # Index the source case-insensitively so we accept either input form.
    lowered = {str(k).lower(): v for k, v in raw.items()}
    out: dict[str, int] = {}
    for label in SEVERITY_LABELS:
        key = label if to_upper else label.lower()
        try:
            out[key] = int(lowered.get(label.lower(), 0) or 0)
        except (TypeError, ValueError):
            out[key] = 0
    return out


def risk_score_from_counts(counts: Mapping[str, Any]) -> float:
    """Compute the 0-100 normalized risk score from a severity-count dict.

    Mirrors the existing formula in scan_utils.summarize_findings_data and the
    inline computation in main.results(), so the number is unchanged. Accepts
    either lower- or upper-cased keys.
    """
    upper = normalize_counts(counts, to_upper=True)
    total_findings = sum(upper.values())
    if total_findings == 0:
        return 0.0
    total_weight = sum(
        SEVERITY_WEIGHTS.get(label, 0.0) * upper.get(label, 0)
        for label in SEVERITY_WEIGHTS
    )
    max_weight = total_findings * SEVERITY_WEIGHTS[Severity.CRITICAL.name]
    return round(min(100.0, (total_weight / max(max_weight, 1.0)) * 100), 1)


def risk_score_from_findings(findings: list[dict]) -> float:
    """Compute the 0-100 risk score directly from a list of finding dicts.

    Convenience wrapper around ``risk_score_from_counts`` for call sites that
    have the raw findings list rather than pre-aggregated counts.
    """
    counts: dict[str, int] = empty_counts()
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        if sev in counts:
            counts[sev] += 1
    return risk_score_from_counts(counts)


def pass_fail_from_counts(counts: Mapping[str, Any]) -> str:
    """Derive PASS / WARNING / FAIL from severity counts.

    Extracted verbatim from the inline logic in main.results() so the gate
    thresholds live in one auditable place.
    """
    upper = normalize_counts(counts, to_upper=True)
    critical = upper.get(Severity.CRITICAL.name, 0)
    high = upper.get(Severity.HIGH.name, 0)
    if critical > 0 or high > 3:
        return "FAIL"
    if high > 0:
        return "WARNING"
    return "PASS"
