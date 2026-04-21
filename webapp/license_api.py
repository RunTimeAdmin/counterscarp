"""Server-side License Validation API for Garrison Engine.

Provides endpoints for license key validation, deactivation,
and info lookups.  These routes are consumed by the client-side
LicenseManager in license_manager.py.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from license_manager import ALL_PRO_FEATURES

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_LICENSE_DB_PATH = Path(__file__).parent.parent / "data" / "licenses.json"
_file_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ValidateRequest(BaseModel):
    license_key: str
    machine_id: str
    product_version: str
    timestamp: str


class ValidateResponse(BaseModel):
    valid: bool
    error: Optional[str] = None
    tier: Optional[str] = None
    expires_at: Optional[str] = None
    features: Optional[List[str]] = None
    max_activations: Optional[int] = None
    current_activations: Optional[int] = None


class DeactivateRequest(BaseModel):
    license_key: str
    machine_id: str


class DeactivateResponse(BaseModel):
    success: bool
    remaining_activations: int


class LicenseInfoResponse(BaseModel):
    key_masked: str
    tier: str
    customer_email: str
    expires_at: str
    max_activations: int
    current_activations: int
    revoked: bool
    created_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_db() -> dict:
    """Load the licenses database from disk."""
    if not _LICENSE_DB_PATH.exists():
        return {"licenses": [], "version": 1}
    with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_db(db: dict) -> None:
    """Persist the licenses database to disk."""
    _LICENSE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_LICENSE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def _mask_key(key: str) -> str:
    """Mask the middle characters of a license key for safe display."""
    parts = key.split("-")
    if len(parts) >= 3:
        # SE-PRO-abc123... → SE-PRO-abc•••••123
        token = parts[-1]
        if len(token) > 6:
            parts[-1] = token[:3] + "•••••" + token[-3:]
    return "-".join(parts)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

license_router = APIRouter(prefix="/api/license", tags=["license"])


@license_router.post("/validate", response_model=ValidateResponse)
def validate_license(req: ValidateRequest):
    """Validate a license key and manage machine activations."""
    with _file_lock:
        db = _load_db()

        # 1. Key exists
        license_entry = None
        for entry in db["licenses"]:
            if entry["key"] == req.license_key:
                license_entry = entry
                break

        if license_entry is None:
            return ValidateResponse(valid=False, error="Invalid license key")

        # 2. Key not revoked
        if license_entry.get("revoked", False):
            return ValidateResponse(valid=False, error="License revoked")

        # 3. Key not expired
        expires_at = license_entry.get("expires_at", "")
        if expires_at:
            try:
                exp_dt = datetime.fromisoformat(
                    expires_at.replace("Z", "+00:00")
                )
                if exp_dt < datetime.now(timezone.utc):
                    return ValidateResponse(
                        valid=False, error="License expired"
                    )
            except (ValueError, TypeError):
                pass  # If we can't parse, allow through

        # 4. Machine activation
        activated: list = license_entry.get("activated_machines", [])
        max_act = license_entry.get("max_activations", 1)

        if req.machine_id in activated:
            # Existing activation — still valid
            pass
        elif len(activated) < max_act:
            # New activation slot available
            activated.append(req.machine_id)
            license_entry["activated_machines"] = activated
            _save_db(db)
        else:
            return ValidateResponse(
                valid=False, error="Maximum activations reached"
            )

        # Determine features based on tier
        tier = license_entry.get("tier", "pro")
        if tier in ("pro", "enterprise"):
            features = list(ALL_PRO_FEATURES)
        else:
            features = []

        return ValidateResponse(
            valid=True,
            tier=tier,
            expires_at=license_entry.get("expires_at"),
            features=features,
            max_activations=max_act,
            current_activations=len(activated),
        )


@license_router.post("/deactivate", response_model=DeactivateResponse)
def deactivate_license(req: DeactivateRequest):
    """Remove a machine activation from a license key."""
    with _file_lock:
        db = _load_db()

        license_entry = None
        for entry in db["licenses"]:
            if entry["key"] == req.license_key:
                license_entry = entry
                break

        if license_entry is None:
            raise HTTPException(
                status_code=404, detail="License key not found"
            )

        activated: list = license_entry.get(
            "activated_machines", []
        )
        if req.machine_id in activated:
            activated.remove(req.machine_id)
            license_entry["activated_machines"] = activated
            _save_db(db)

        return DeactivateResponse(
            success=True,
            remaining_activations=len(activated),
        )


@license_router.get("/info", response_model=LicenseInfoResponse)
def license_info(key: str = Query(..., description="License key to look up")):
    """Admin endpoint: look up license details (key is masked in response)."""
    with _file_lock:
        db = _load_db()

        license_entry = None
        for entry in db["licenses"]:
            if entry["key"] == key:
                license_entry = entry
                break

        if license_entry is None:
            raise HTTPException(
                status_code=404, detail="License key not found"
            )

        return LicenseInfoResponse(
            key_masked=_mask_key(license_entry["key"]),
            tier=license_entry.get("tier", "pro"),
            customer_email=license_entry.get("customer_email", ""),
            expires_at=license_entry.get("expires_at", ""),
            max_activations=license_entry.get("max_activations", 1),
            current_activations=len(
                license_entry.get("activated_machines", [])
            ),
            revoked=license_entry.get("revoked", False),
            created_at=license_entry.get("created_at", ""),
        )
