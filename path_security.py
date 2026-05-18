from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Set

from exceptions import CounterscarpValidationError


def _normalize_suffixes(allowed_suffixes: Optional[Iterable[str]]) -> Set[str]:
    if not allowed_suffixes:
        return set()
    return {s.lower() for s in allowed_suffixes}


def sanitize_cli_path(
    path_value: str,
    *,
    allowed_suffixes: Optional[Iterable[str]] = None,
    must_exist: bool = True,
    expect_file: bool = True,
) -> Path:
    """Validate a user-provided filesystem path before use.

    Rejects obvious traversal patterns and malformed values, then returns
    a normalized absolute path.
    """
    if not isinstance(path_value, str):
        raise CounterscarpValidationError(
            "Path must be a string",
            details={"value_type": type(path_value).__name__},
        )

    cleaned = path_value.strip()
    if not cleaned:
        raise CounterscarpValidationError("Path cannot be empty")
    if "\x00" in cleaned:
        raise CounterscarpValidationError("Path contains invalid null byte")

    raw = Path(cleaned).expanduser()
    if ".." in raw.parts:
        raise CounterscarpValidationError(
            "Path traversal sequence is not allowed",
            details={"path": cleaned},
        )

    resolved = raw.resolve(strict=False)
    if must_exist and not resolved.exists():
        raise CounterscarpValidationError(
            "Path does not exist",
            details={"path": str(resolved)},
        )

    if must_exist and expect_file and not resolved.is_file():
        raise CounterscarpValidationError(
            "Expected a file path",
            details={"path": str(resolved)},
        )
    if must_exist and not expect_file and not resolved.is_dir():
        raise CounterscarpValidationError(
            "Expected a directory path",
            details={"path": str(resolved)},
        )

    allowed = _normalize_suffixes(allowed_suffixes)
    if allowed and expect_file and resolved.suffix.lower() not in allowed:
        raise CounterscarpValidationError(
            "Unsupported file extension",
            details={"path": str(resolved), "allowed_suffixes": sorted(allowed)},
        )

    return resolved


def sanitize_output_path(path_value: str) -> Path:
    """Validate an output file path that may not exist yet."""
    if not isinstance(path_value, str):
        raise CounterscarpValidationError(
            "Output path must be a string",
            details={"value_type": type(path_value).__name__},
        )
    cleaned = path_value.strip()
    if not cleaned:
        raise CounterscarpValidationError("Output path cannot be empty")
    if "\x00" in cleaned:
        raise CounterscarpValidationError("Output path contains invalid null byte")

    raw = Path(cleaned).expanduser()
    if ".." in raw.parts:
        raise CounterscarpValidationError(
            "Path traversal sequence is not allowed in output path",
            details={"path": cleaned},
        )
    return raw.resolve(strict=False)
