"""At-rest encryption helpers for JSON data stores.

When DATA_ENCRYPTION_KEY is set, all JSON reads and writes through this
module are transparently encrypted with Fernet symmetric encryption.
In production (COUNTERSCARP_ENV=production), the key is mandatory and
startup will fail without it. In development it is optional with a warning.

Migration: if decryption of an existing file fails, the file is read as
plain JSON and will be re-written in encrypted form on the next write.
This provides a seamless upgrade path for existing deployments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False


def _build_fernet(key_material: str) -> "Fernet":
    digest = hashlib.sha256(key_material.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _init_fernet() -> Optional["Fernet"]:
    key_env = os.environ.get("DATA_ENCRYPTION_KEY", "").strip()
    if not key_env:
        env = os.environ.get("COUNTERSCARP_ENV", "development")
        if env == "production":
            raise RuntimeError(
                "DATA_ENCRYPTION_KEY must be set in production for at-rest "
                "encryption of data stores. "
                "Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        _logger.warning(
            "DATA_ENCRYPTION_KEY not set — JSON data stores (users, licenses) "
            "are stored unencrypted on disk. Set this variable before going to production."
        )
        return None
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required when DATA_ENCRYPTION_KEY is set."
        )
    return _build_fernet(key_env)


# Evaluated once at import time — fails fast in production without the key.
_fernet: Optional["Fernet"] = _init_fernet()


def read_json(path: Path, default: Any) -> Any:
    """Read and optionally decrypt a JSON file.

    Falls back to plain JSON parsing on decryption failure to support
    migration from unencrypted to encrypted stores.
    """
    if not path.exists():
        return default
    raw = path.read_bytes()
    if _fernet is not None:
        try:
            raw = _fernet.decrypt(raw)
        except Exception:
            _logger.warning(
                "Could not decrypt %s — reading as plain JSON (migration). "
                "File will be re-written encrypted on next write.",
                path.name,
            )
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _logger.error("Failed to parse %s — returning default value", path.name)
        return default


def write_json(path: Path, data: Any) -> None:
    """Serialize *data* to JSON and optionally encrypt before writing.

    Uses an atomic tmp-then-rename pattern to prevent partial writes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    serialized = json.dumps(data, indent=2)
    if _fernet is not None:
        raw = _fernet.encrypt(serialized.encode("utf-8"))
        tmp.write_bytes(raw)
    else:
        tmp.write_text(serialized, encoding="utf-8")
    tmp.replace(path)
