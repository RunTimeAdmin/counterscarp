"""GAME custom functions that call Counterscarp."""

from __future__ import annotations

import json
from typing import Tuple

from game_sdk.game.custom_types import FunctionResultStatus

from counterscarp_client import CounterscarpClient

_client: CounterscarpClient | None = None


def _get_client() -> CounterscarpClient:
    global _client
    if _client is None:
        _client = CounterscarpClient()
    return _client


def scan_contract(
    filename: str,
    source_code: str,
    project_name: str = "",
    **kwargs,
) -> Tuple[FunctionResultStatus, str, dict]:
    """Run a full Counterscarp audit on contract source."""
    try:
        name = (filename or "").strip()
        code = (source_code or "").strip()
        if not name.lower().endswith((".sol", ".rs")):
            return (
                FunctionResultStatus.FAILED,
                "Only .sol and .rs files are supported",
                {},
            )
        if not code:
            return FunctionResultStatus.FAILED, "source_code is empty", {}

        result = _get_client().scan_contract(
            filename=name,
            content=code,
            project_name=project_name or name,
        )
        summary = result.get("summary") or {}
        severity = summary.get("severity_counts") or {}
        message = (
            f"Scan complete for {name}. "
            f"Risk score {summary.get('risk_score', 'n/a')}/100. "
            f"{summary.get('total_findings', 0)} findings "
            f"(critical={severity.get('critical', 0)}, "
            f"high={severity.get('high', 0)}, "
            f"medium={severity.get('medium', 0)}, "
            f"low={severity.get('low', 0)})."
        )
        if result.get("ai_summary"):
            message += f" AI summary: {result['ai_summary'][:400]}"

        findings = result.get("findings") or []
        top = findings[:3]
        if top:
            highlights = []
            for item in top:
                highlights.append(
                    f"{item.get('severity', '?')}: {item.get('title', item.get('rule_id', '?'))}"
                )
            message += " Top issues: " + "; ".join(highlights) + "."

        info = {
            "audit_id": result.get("audit_id"),
            "summary": summary,
            "report_urls": result.get("report_urls", {}),
            "finding_count": len(findings),
        }
        return FunctionResultStatus.DONE, message, info
    except Exception as exc:
        return FunctionResultStatus.FAILED, f"Counterscarp scan failed: {exc}", {}


def get_scan_status(
    audit_id: str,
    **kwargs,
) -> Tuple[FunctionResultStatus, str, dict]:
    """Fetch status for an existing scan."""
    try:
        audit_id = (audit_id or "").strip()
        if not audit_id:
            return FunctionResultStatus.FAILED, "audit_id is required", {}
        data = _get_client().get_scan(audit_id, include_findings=True)
        return (
            FunctionResultStatus.DONE,
            json.dumps(data, indent=2)[:4000],
            data,
        )
    except Exception as exc:
        return FunctionResultStatus.FAILED, str(exc), {}
