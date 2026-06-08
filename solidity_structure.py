"""Lightweight Solidity structure extraction for graph and analysis tools.

Uses comment stripping and brace matching — not a full AST — but correctly
scopes functions to contracts and maps line numbers to containing functions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from path_security import sanitize_cli_path

CONTRACT_HEADER_RE = re.compile(
    r"\b(?:contract|interface|library)\s+(\w+)\s*(?:is\s+([^{;]+))?\s*\{",
    re.MULTILINE,
)

FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+(\w+)\s*\(",
    re.MULTILINE,
)

EXTERNAL_CALL_RE = re.compile(
    r"(\w+)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*[\{\(]",
    re.MULTILINE,
)

_VISIBILITY_KEYWORDS = ("external", "public", "internal", "private")
_ASSIGNMENT_KEYWORD_BLOCKLIST = frozenset(
    {"return", "if", "for", "while", "require", "assert", "emit", "revert"}
)


def strip_solidity_comments(content: str) -> str:
    """Remove // and /* */ comments while preserving newlines for line numbers."""
    without_block = re.sub(
        r"/\*.*?\*/",
        lambda match: " " * (match.end() - match.start()),
        content,
        flags=re.DOTALL,
    )
    return re.sub(r"//[^\n]*", "", without_block)


def _line_number(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


def _find_matching_brace(content: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(content)):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _function_header_end(content: str, start: int) -> Tuple[int, bool]:
    """Return index after function declaration and whether a braced body exists."""
    paren_depth = 0
    idx = start
    while idx < len(content):
        char = content[idx]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
            if paren_depth == 0:
                idx += 1
                break
        idx += 1
    else:
        return start, False

    while idx < len(content) and content[idx] not in "{;":
        idx += 1

    if idx >= len(content):
        return start, False

    if content[idx] == ";":
        return idx + 1, False

    body_end = _find_matching_brace(content, idx)
    if body_end == -1:
        return idx + 1, False
    return body_end + 1, True


def _parse_visibility(header: str) -> str:
    for keyword in _VISIBILITY_KEYWORDS:
        if re.search(rf"\b{keyword}\b", header):
            return keyword
    return "internal"


def parse_solidity_structure(content: str) -> Dict[str, Any]:
    """Parse contracts, scoped functions, external calls, and state writes."""
    cleaned = strip_solidity_comments(content)
    result: Dict[str, Any] = {
        "contracts": [],
        "functions": [],
        "external_calls": [],
        "state_writes": [],
    }

    for contract_match in CONTRACT_HEADER_RE.finditer(cleaned):
        contract_name = contract_match.group(1)
        inheritance_raw = contract_match.group(2) or ""
        body_open = contract_match.end() - 1
        body_close = _find_matching_brace(cleaned, body_open)
        if body_close == -1:
            continue

        contract_start_line = _line_number(content, contract_match.start())
        contract_end_line = _line_number(content, body_close)
        inheritance = [
            part.strip()
            for part in inheritance_raw.split(",")
            if part.strip()
        ]

        result["contracts"].append(
            {
                "name": contract_name,
                "line": contract_start_line,
                "end_line": contract_end_line,
                "inheritance": inheritance,
            }
        )

        contract_body = cleaned[body_open + 1 : body_close]
        body_offset = body_open + 1

        for func_match in FUNCTION_HEADER_RE.finditer(contract_body):
            func_name = func_match.group(1)
            abs_start = body_offset + func_match.start()
            header_end, _has_body = _function_header_end(
                cleaned, abs_start
            )
            header_text = cleaned[abs_start:header_end]
            func_start_line = _line_number(content, abs_start)
            func_end_line = _line_number(content, max(abs_start, header_end - 1))

            result["functions"].append(
                {
                    "name": func_name,
                    "contract": contract_name,
                    "line": func_start_line,
                    "end_line": func_end_line,
                    "visibility": _parse_visibility(header_text),
                    "modifiers": header_text.strip(),
                }
            )

        for call_match in EXTERNAL_CALL_RE.finditer(contract_body):
            abs_start = body_offset + call_match.start()
            result["external_calls"].append(
                {
                    "target": call_match.group(1),
                    "call_type": call_match.group(2),
                    "line": _line_number(content, abs_start),
                    "contract": contract_name,
                }
            )

    lines = cleaned.split("\n")
    for line_no, line in enumerate(lines, 1):
        for match in re.finditer(r"\b(\w+)\s*=[^=]", line):
            var_name = match.group(1)
            if var_name not in _ASSIGNMENT_KEYWORD_BLOCKLIST:
                result["state_writes"].append(
                    {"variable": var_name, "line": line_no}
                )

    return result


def function_containing_line(
    functions: List[Dict[str, Any]], line_no: int, contract: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Return the innermost function whose span contains *line_no*."""
    candidates = [
        func
        for func in functions
        if func["line"] <= line_no <= func.get("end_line", func["line"])
        and (contract is None or func.get("contract") == contract)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda func: func["line"])


def parse_solidity_file(file_path: str) -> Dict[str, Any]:
    """Read and structurally parse a Solidity source file."""
    safe_path = sanitize_cli_path(file_path, allowed_suffixes={".sol"})
    try:
        content = safe_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return parse_solidity_structure(content)
