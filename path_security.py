from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Iterable, Optional, Set

from exceptions import CounterscarpValidationError

_SOLIDITY_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GIT_BRANCH_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")
_GIT_SINCE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    confined_to: Optional[Path] = None,
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

    if confined_to is not None:
        root = confined_to.expanduser().resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise CounterscarpValidationError(
                "Path escapes allowed root",
                details={"path": str(resolved), "root": str(root)},
            ) from exc

    return resolved


def validate_solidity_identifier(name: str, *, field_name: str = "name") -> str:
    """Validate a Solidity contract or function identifier."""
    cleaned = (name or "").strip()
    if not cleaned or not _SOLIDITY_IDENTIFIER_RE.match(cleaned):
        raise CounterscarpValidationError(
            f"Invalid Solidity identifier for {field_name}",
            details={field_name: name},
        )
    return cleaned


def validate_git_branch_name(branch: str) -> str:
    """Reject git option injection via branch names."""
    cleaned = (branch or "").strip()
    if not cleaned or cleaned.startswith("-"):
        raise CounterscarpValidationError(
            "Invalid branch name",
            details={"branch": branch},
        )
    if ".." in cleaned or cleaned.endswith(".lock"):
        raise CounterscarpValidationError(
            "Branch name contains invalid sequence",
            details={"branch": branch},
        )
    if not _GIT_BRANCH_RE.match(cleaned):
        raise CounterscarpValidationError(
            "Branch name contains invalid characters",
            details={"branch": branch},
        )
    return cleaned


def validate_git_since_date(since: str) -> str:
    """Validate --since filter as ISO date YYYY-MM-DD."""
    cleaned = (since or "").strip()
    if not _GIT_SINCE_RE.match(cleaned):
        raise CounterscarpValidationError(
            "--since must be ISO date format YYYY-MM-DD",
            details={"since": since},
        )
    return cleaned


def write_private_file(path: Path, content: str) -> None:
    """Write a secrets file with owner-only permissions (0o600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


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


def sanitize_scan_target(path_value: str) -> Path:
    """Validate a scan target path that may be a .sol file or project directory."""
    if not isinstance(path_value, str):
        raise CounterscarpValidationError(
            "Target path must be a string",
            details={"value_type": type(path_value).__name__},
        )

    cleaned = path_value.strip()
    if not cleaned:
        raise CounterscarpValidationError("Target path cannot be empty")

    raw = Path(cleaned).expanduser()
    if ".." in raw.parts:
        raise CounterscarpValidationError(
            "Path traversal sequence is not allowed",
            details={"path": cleaned},
        )

    resolved_hint = raw.resolve(strict=False)
    if resolved_hint.exists():
        expect_file = resolved_hint.is_file()
    else:
        expect_file = raw.suffix.lower() == ".sol"

    if expect_file:
        return sanitize_cli_path(
            path_value,
            must_exist=True,
            expect_file=True,
            allowed_suffixes={".sol"},
        )
    return sanitize_cli_path(
        path_value,
        must_exist=True,
        expect_file=False,
    )


def sanitize_project_slug(name: str) -> str:
    """Sanitize a user-supplied project name for use as a directory component."""
    slug = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in (name or "").strip()
    )
    slug = slug.strip("_") or "scan"
    if slug in {".", ".."}:
        return "scan"
    return slug[:64]
