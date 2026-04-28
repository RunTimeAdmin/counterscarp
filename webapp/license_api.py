"""Server-side License Validation API for Counterscarp Engine.

Provides endpoints for license key validation, deactivation,
and info lookups.  These routes are consumed by the client-side
LicenseManager in license_manager.py.
"""

import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints

from license_manager import ALL_PRO_FEATURES
from webapp.rate_limiter import RateLimiter, add_rate_limit_headers

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("counterscarp.security")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_LICENSE_DB_PATH = Path(__file__).parent.parent / "data" / "licenses.json"
_AUDIT_LOG_PATH = Path(__file__).parent.parent / "data" / "audit_log.jsonl"
_licenses_file_lock = threading.Lock()
_audit_log_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Audit trail logging
# ---------------------------------------------------------------------------


def append_audit_log(event_type: str, key: str, actor: str, ip: str, changes: dict) -> None:
    """Append a single JSON line to the audit log (thread-safe, append-only)."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "key": key[:12] + "..." if key else "",
        "actor": actor,
        "ip": ip,
        "changes": changes,
    }
    with _audit_log_lock:
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")


# ---------------------------------------------------------------------------
# Public helper — license linking
# ---------------------------------------------------------------------------


def link_license_to_user(email: str, user_id: str) -> Optional[str]:
    """Atomically link first unlinked license for *email* to *user_id*. Returns key or None."""
    key: Optional[str] = None
    with _licenses_file_lock:
        if not _LICENSE_DB_PATH.exists():
            return None
        try:
            with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as f:
                db = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        for lic in db.get("licenses", []):
            if lic.get("customer_email", "").lower() == email.lower() and not lic.get("user_id"):
                lic["user_id"] = user_id
                tmp = _LICENSE_DB_PATH.with_suffix(".tmp")
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(db, f, indent=2)
                tmp.replace(_LICENSE_DB_PATH)
                key = str(lic["key"])
                break
    if key:
        append_audit_log("license_linked", key, user_id, "system", {"email": email})
    return key


def consume_credit(user_id: str, audit_id: str, ip: str) -> bool:
    """Atomically consume one scan credit for a PAYG user.

    Returns True if a credit was successfully consumed, False if no credits remain.
    Thread-safe: holds user_manager's file lock for the entire read-check-write cycle.
    """
    from webapp.user_manager import user_manager as _um

    # Use user_manager's internal lock for atomic read-check-write
    with _um._file_lock:
        db = _um._load_db()
        for u in db.get("users", []):
            if u["id"] == user_id:
                current_credits = u.get("scan_credits", 0)
                if current_credits <= 0:
                    return False
                u["scan_credits"] = current_credits - 1
                u["credits_used"] = u.get("credits_used", 0) + 1
                _um._write_db(db)
                break
        else:
            return False

    # Log outside the user lock (audit log has its own lock)
    append_audit_log(
        event_type="payg_credit_consumed",
        key=audit_id,
        actor=user_id,
        ip=ip,
        changes={"credits_before": current_credits, "credits_after": current_credits - 1, "audit_id": audit_id},
    )
    return True


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ValidateRequest(BaseModel):
    license_key: Annotated[str, StringConstraints(
        pattern=r'^SE-(DEV|PRO|TEAM|ENT)-[0-9a-f]{32}$'
    )]
    machine_id: Annotated[str, StringConstraints(
        max_length=255,
        pattern=r'^[a-zA-Z0-9\-_:.]{1,255}$'
    )]
    product_version: Annotated[str, StringConstraints(
        pattern=r'^\d+\.\d+\.\d+.*$',
        max_length=20
    )]
    timestamp: Annotated[str, StringConstraints(
        pattern=r'^\d{4}-\d{2}-\d{2}T[\d:.]+[Z+\-\d:]*$',
        max_length=40
    )]


class ValidateResponse(BaseModel):
    valid: bool
    error: Optional[str] = None
    tier: Optional[str] = None
    expires_at: Optional[str] = None
    features: Optional[List[str]] = None
    max_activations: Optional[int] = None
    current_activations: Optional[int] = None


class DeactivateRequest(BaseModel):
    license_key: Annotated[str, StringConstraints(
        pattern=r'^SE-(DEV|PRO|TEAM|ENT)-[0-9a-f]{32}$'
    )]
    machine_id: Annotated[str, StringConstraints(
        max_length=255,
        pattern=r'^[a-zA-Z0-9\-_:.]{1,255}$'
    )]


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


_DEFAULT_DB: dict = {"licenses": [], "version": 1}


def _load_db() -> dict[str, Any]:
    """Load the licenses database from disk."""
    if not _LICENSE_DB_PATH.exists():
        return {"licenses": [], "version": 1}
    with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as f:
        db: dict[str, Any] = json.load(f)
    # Validate structure — guard against corrupted files
    if not isinstance(db.get("licenses"), list):
        logger.error(
            "licenses.json has invalid structure (expected 'licenses' list); "
            "returning default empty database"
        )
        return {"licenses": [], "version": 1}
    return db


def _save_db(db: dict) -> None:
    """Persist the licenses database to disk (atomic write)."""
    _LICENSE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _LICENSE_DB_PATH.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    temp_path.replace(_LICENSE_DB_PATH)


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

# Rate limiters — module-level singletons (in-memory, no extra deps)
_validate_limiter = RateLimiter(max_requests=10, window_seconds=60)
_deactivate_limiter = RateLimiter(max_requests=5, window_seconds=60)


@license_router.post("/validate", response_model=ValidateResponse)
def validate_license(req: ValidateRequest, request: Request):
    """Validate a license key and manage machine activations."""
    client_ip = request.client.host if request.client else "unknown"
    if not _validate_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(
            resp_429, _validate_limiter, client_ip,
        )
        resp_429.headers["Retry-After"] = str(
            _validate_limiter.get_reset_time(client_ip)
        )
        return resp_429
    try:
        audit_data = None  # Collect audit info inside lock, log outside
        with _licenses_file_lock:
            try:
                db = _load_db()
            except json.JSONDecodeError as exc:
                logger.error("License database JSON is corrupted: %s", exc)
                return ValidateResponse(valid=False, error="License database error")
            except (OSError, PermissionError) as exc:
                logger.error("License database file error: %s", exc)
                return ValidateResponse(
                    valid=False, error="License service temporarily unavailable"
                )

            # 1. Key exists
            license_entry = None
            for entry in db["licenses"]:
                if entry["key"] == req.license_key:
                    license_entry = entry
                    break

            if license_entry is None:
                security_logger.warning(
                    "License validation failed: key=%s ip=%s reason=%s",
                    req.license_key[:10] + "...", client_ip, "invalid_key",
                )
                return ValidateResponse(valid=False, error="Invalid license key")

            # 2. Key not revoked
            if license_entry.get("revoked", False):
                security_logger.warning(
                    "License validation failed: key=%s ip=%s reason=%s",
                    req.license_key[:10] + "...", client_ip, "key_revoked",
                )
                return ValidateResponse(valid=False, error="License revoked")

            # 3. Key not expired (with Stripe subscription fallback)
            expires_at = license_entry.get("expires_at", "")
            license_appears_expired = False
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(
                        expires_at.replace("Z", "+00:00")
                    )
                    if exp_dt < datetime.now(timezone.utc):
                        license_appears_expired = True
                except (ValueError, TypeError):
                    pass  # If we can't parse, allow through

            if license_appears_expired and license_entry.get("stripe_subscription_id"):
                # Missed renewal webhook — check Stripe directly
                try:
                    import stripe
                    stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
                    if not stripe.api_key:
                        security_logger.warning(
                            "STRIPE_SECRET_KEY not set — cannot verify subscription status via Stripe"
                        )
                    if stripe.api_key:
                        sub = stripe.Subscription.retrieve(
                            license_entry["stripe_subscription_id"]
                        )
                        if sub.status == "active":
                            # Stripe says still active — extend local expiry
                            interval = license_entry.get("billing_interval", "month")
                            now = datetime.now(timezone.utc)
                            new_expiry = now + timedelta(
                                days=365 if interval == "year" else 30
                            )
                            from webapp.stripe_integration import update_license_in_db
                            update_license_in_db(
                                license_entry["key"],
                                {"expires_at": new_expiry.strftime("%Y-%m-%d")},
                            )
                            logger.info(
                                "License %s... renewed via Stripe status check",
                                license_entry["key"][:12],
                            )
                            license_appears_expired = False
                except Exception as e:
                    logger.warning("Stripe subscription check failed: %s", e)
                    # Fall through to expiry decision below

            if license_appears_expired:
                security_logger.warning(
                    "License validation failed: key=%s ip=%s reason=%s",
                    req.license_key[:10] + "...", client_ip, "key_expired",
                )
                return ValidateResponse(valid=False, error="License expired")

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
                audit_data = {"machine_id": req.machine_id}
            else:
                security_logger.warning(
                    "License validation failed: key=%s ip=%s reason=%s",
                    req.license_key[:10] + "...", client_ip, "max_activations_reached",
                )
                return ValidateResponse(
                    valid=False, error="Maximum activations reached"
                )

            # Determine features based on tier
            tier = license_entry.get("tier", "pro")
            if tier in ("pro", "enterprise"):
                features = list(ALL_PRO_FEATURES)
            else:
                features = []

            result = ValidateResponse(
                valid=True,
                tier=tier,
                expires_at=license_entry.get("expires_at"),
                features=features,
                max_activations=max_act,
                current_activations=len(activated),
            )

        # Audit log OUTSIDE the license lock
        if audit_data is not None:
            append_audit_log(
                "license_activated", req.license_key, "system",
                client_ip, audit_data,
            )
        return result

    except Exception as exc:
        logger.exception(
            "Unexpected error in validate_license: %s", exc,
        )
        return ValidateResponse(
            valid=False, error="License validation failed",
        )


@license_router.post("/deactivate", response_model=DeactivateResponse)
def deactivate_license(req: DeactivateRequest, request: Request):
    """Remove a machine activation from a license key."""
    client_ip = request.client.host if request.client else "unknown"
    if not _deactivate_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(
            resp_429, _deactivate_limiter, client_ip,
        )
        resp_429.headers["Retry-After"] = str(
            _deactivate_limiter.get_reset_time(client_ip)
        )
        return resp_429
    deactivated = False
    remaining = 0
    with _licenses_file_lock:
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
            deactivated = True
        remaining = len(activated)

    # Audit log and security log OUTSIDE the license lock
    if deactivated:
        security_logger.info(
            "License deactivation: key=%s machine=%s ip=%s",
            req.license_key[:10] + "...", req.machine_id, client_ip,
        )
        append_audit_log(
            "license_deactivated", req.license_key, "system",
            client_ip, {"machine_id": req.machine_id},
        )

    return DeactivateResponse(
        success=True,
        remaining_activations=remaining,
        )


@license_router.get("/info", response_model=LicenseInfoResponse)
def license_info(request: Request, key: str = Query(..., description="License key to look up")):
    """Admin endpoint: look up license details (requires admin authentication)."""
    # --- Admin authentication check ---
    user_id = request.session.get("user_id") if hasattr(request, "session") else None
    if not user_id:
        raise HTTPException(status_code=403, detail="Authentication required")
    from webapp.config import ADMIN_EMAIL
    from webapp.user_manager import UserManager
    um = UserManager()
    user = um.get_by_id(user_id)
    if not user or user.get("email") != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required")
    # --- License lookup ---
    with _licenses_file_lock:
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

        client_ip = request.client.host if request.client else "unknown"
        security_logger.info(
            "Admin license info accessed: key=%s ip=%s user=%s",
            _mask_key(key), client_ip, user.get("email", "unknown"),
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
