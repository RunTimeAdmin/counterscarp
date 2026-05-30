"""Bearer API key authentication for machine-facing endpoints."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ApiClient:
    """Authenticated API client derived from a configured key."""

    client_id: str
    key_fingerprint: str


def _fingerprint(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return digest[:12]


def load_api_keys() -> Dict[str, str]:
    """Load ``client_id -> secret`` pairs from ``COUNTERSCARP_API_KEYS``.

    Format: ``label:secret,label2:secret2`` or bare secrets (auto-labeled).
    """
    raw = os.environ.get("COUNTERSCARP_API_KEYS", "").strip()
    if not raw:
        single = os.environ.get("COUNTERSCARP_API_KEY", "").strip()
        if single:
            raw = single
    if not raw:
        return {}

    keys: Dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            label, secret = entry.split(":", 1)
            label = label.strip()
            secret = secret.strip()
        else:
            secret = entry
            label = f"key-{_fingerprint(secret)}"
        if not secret:
            continue
        keys[label] = secret
    return keys


def verify_api_key(secret: str) -> Optional[ApiClient]:
    """Return the matching client if *secret* is valid."""
    for client_id, configured in load_api_keys().items():
        if hmac.compare_digest(secret, configured):
            return ApiClient(
                client_id=client_id,
                key_fingerprint=_fingerprint(secret),
            )
    return None


async def require_api_client(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> ApiClient:
    """FastAPI dependency: require ``Authorization: Bearer <key>``."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail=(
                "Missing or invalid Authorization header. "
                "Use: Bearer <api_key>"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )
    client = verify_api_key(credentials.credentials)
    if client is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return client
