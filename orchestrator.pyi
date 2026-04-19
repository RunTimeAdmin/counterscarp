from __future__ import annotations

from typing import List, Dict, Optional, Any


def get_remediation(issue_type: str, context: str) -> str: ...
def generate_markdown_report(
    project_name: str,
    static_results: List[Dict[str, Any]],
    supply_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    symbolic_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]] = None,
    medusa_results: Optional[Dict[str, Any]] = None,
    solana_results: Optional[Dict[str, Any]] = None,
    upgrade_results: Optional[Dict[str, Any]] = None,
    fingerprint_results: Optional[List[Dict[str, Any]]] = None,
) -> str: ...
def main() -> None: ...
