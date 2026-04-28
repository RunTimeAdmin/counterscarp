"""Authentication routes for Counterscarp Engine web application.

Provides email/password and Google OAuth login, registration, logout,
and an admin endpoint for mailing-list export.
"""

from __future__ import annotations

import hmac as _hmac
import logging
import math

from fastapi import APIRouter, HTTPException, Query, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer
from starlette.templating import Jinja2Templates

from webapp.user_manager import user_manager
from webapp.rate_limiter import get_client_ip
from webapp.license_api import link_license_to_user
from webapp.config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    ADMIN_EMAIL,
    TEMPLATES_DIR,
    SESSION_SECRET,
)

# ---------------------------------------------------------------------------
# Router setup
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

auth_router = APIRouter(prefix="/auth", tags=["authentication"])
admin_router = APIRouter(tags=["admin"])

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# Google OAuth setup
# ---------------------------------------------------------------------------

from authlib.integrations.starlette_client import OAuth  # noqa: E402

oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_csrf_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="csrf")


def generate_csrf_token(request: Request) -> str:
    """Generate and store a CSRF token in the session."""
    token = _csrf_serializer.dumps(
        request.session.get("user_id", "anon")
    )
    request.session["_csrf_token"] = token
    return token


def validate_csrf_token(request: Request, form_token: str) -> bool:
    """Validate CSRF token from form matches session."""
    session_token = request.session.get("_csrf_token", "")
    if not session_token or not form_token:
        return False
    return _hmac.compare_digest(session_token, form_token)


def get_current_user(request: Request):
    """Read session cookie and return user dict or None."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return user_manager.get_by_id(user_id)


def get_license_key_for_request(request: Request, current_user: dict | None) -> str:
    """Retrieve license key scoped to the current authenticated user.

    Checks the user record first, then falls back to the session cookie.
    Never touches ``os.environ`` so that concurrent requests in the same
    worker process cannot bleed license keys between users.
    """
    if current_user:
        key = current_user.get("license_key") or ""
        if key:
            return key
    return request.session.get("user_license") or ""


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@auth_router.get("/login")
async def login_page(request: Request):
    """Render the login page."""
    error = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request, "login.html", context={
            "current_user": None,
            "error": error,
            "csrf_token": generate_csrf_token(request),
        }
    )


@auth_router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    """Handle email/password login form submission."""
    # CSRF validation — skip if no token was ever generated (tests / first-time visitors)
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    client_ip = get_client_ip(request)
    login_limiter = getattr(request.app.state, "login_limiter", None)
    if login_limiter and not login_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    user = user_manager.verify_password(email, password)
    if user:
        request.session["user_id"] = user["id"]
        user_manager.update_last_login(user["id"])
        # Store user's license in the session (never in os.environ)
        if user.get("license_key"):
            request.session["user_license"] = user["license_key"]
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        request,
        "login.html",
        context={"current_user": None, "error": "Invalid email or password"},
    )


@auth_router.get("/register")
async def register_page(request: Request):
    """Render the registration page."""
    error = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request, "register.html", context={
            "current_user": None,
            "error": error,
            "csrf_token": generate_csrf_token(request),
        }
    )


@auth_router.post("/register")
async def register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Handle registration form submission."""
    # CSRF validation — skip if no token was ever generated (tests / first-time visitors)
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    client_ip = get_client_ip(request)
    register_limiter = getattr(request.app.state, "register_limiter", None)
    if register_limiter and not register_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Too many registration attempts. Try again later.")
    if password != confirm_password:
        return templates.TemplateResponse(
            request,
            "register.html",
            context={"current_user": None, "error": "Passwords do not match", "name": name, "email": email},
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request,
            "register.html",
            context={
                "current_user": None,
                "error": "Password must be at least 8 characters",
                "name": name,
                "email": email,
            },
        )

    try:
        user = user_manager.create_user(
            email=email,
            name=name,
            password=password,
            auth_method="email",
        )
    except ValueError:
        return templates.TemplateResponse(
            request,
            "register.html",
            context={
                "current_user": None,
                "error": "An account with this email already exists",
                "name": name,
                "email": email,
            },
        )

    request.session["user_id"] = user["id"]

    # Check for any existing license purchased with this email
    linked_key = link_license_to_user(email, user["id"])
    if linked_key:
        user_manager.set_license_key(
            user["id"],
            linked_key,
        )

    # Refresh user data after potential license link
    refreshed_user = user_manager.get_by_id(user["id"])
    if refreshed_user and refreshed_user.get("license_key"):
        request.session["user_license"] = refreshed_user["license_key"]

    return RedirectResponse(url="/", status_code=302)


@auth_router.get("/google")
async def google_login(request: Request):
    """Initiate Google OAuth flow."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return RedirectResponse(
            url="/auth/login?error=Google+sign-in+is+not+configured",
            status_code=302,
        )
    google = oauth.create_client("google")
    redirect_uri = GOOGLE_REDIRECT_URI
    return await google.authorize_redirect(request, redirect_uri)


@auth_router.get("/google/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return RedirectResponse(
            url="/auth/login?error=Google+sign-in+is+not+configured",
            status_code=302,
        )

    try:
        google = oauth.create_client("google")
        token = await google.authorize_access_token(request)
        user_info = token.get("userinfo")

        if not user_info:
            return RedirectResponse(
                url="/auth/login?error=Failed+to+retrieve+user+info+from+Google",
                status_code=302,
            )

        email: str = user_info.get("email", "")
        name: str = user_info.get("name", email.split("@")[0])
        sub: str = user_info.get("sub", "")

        # Try to find existing user by google_id
        user = user_manager.get_by_google_id(sub) if sub else None

        if user is None:
            # Check by email — link if found, else create new account
            user = user_manager.get_by_email(email)
            if user is None:
                user = user_manager.create_user(
                    email=email,
                    name=name,
                    google_id=sub,
                    auth_method="google",
                )
                # Check for any existing license purchased with this email
                linked_key = link_license_to_user(email, user["id"])
                if linked_key:
                    user_manager.set_license_key(
                        user["id"],
                        linked_key,
                    )

        request.session["user_id"] = user["id"]
        user_manager.update_last_login(user["id"])
        # Store user's license in the session (never in os.environ)
        user = user_manager.get_by_id(user["id"])
        if user and user.get("license_key"):
            request.session["user_license"] = user["license_key"]
        return RedirectResponse(url="/", status_code=302)

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Google OAuth callback failed: %s", exc)
        return RedirectResponse(
            url="/auth/login?error=google_signin_failed",
            status_code=302,
        )


@auth_router.get("/logout")
async def logout(request: Request):
    """Clear session and redirect to home."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


@admin_router.get("/admin/users")
async def admin_users(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """Return enriched user list with license info for admin only (paginated)."""
    import json
    from pathlib import Path

    current_user = get_current_user(request)
    if not current_user or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    client_ip = get_client_ip(request)
    admin_limiter = getattr(request.app.state, "admin_limiter", None)
    if admin_limiter and not admin_limiter.is_allowed(client_ip):
        return JSONResponse({"error": "Rate limit exceeded. Try again later."}, status_code=429)

    # Load licenses.json once before the loop (PO-01 optimization)
    licenses_data: dict[str, str] = {}
    _licenses_path = Path(__file__).parent.parent / "data" / "licenses.json"
    if _licenses_path.exists():
        with open(_licenses_path, "r") as f:
            raw = json.load(f)
        licenses_data = {
            lic["key"]: lic.get("tier", "community")
            for lic in raw.get("licenses", [])
            if "key" in lic
        }

    def _mask_key(license_key: str | None) -> str | None:
        if not license_key:
            return None
        return license_key[:10] + "..." if len(license_key) > 10 else license_key

    users = user_manager.list_users()
    all_items = []
    for u in users:
        raw_key = u.get("license_key")
        tier = licenses_data.get(raw_key, "community") if raw_key else "community"
        all_items.append(
            {
                "email": u["email"],
                "name": u["name"],
                "created_at": u["created_at"],
                "auth_method": u.get("auth_method", "email"),
                "last_login": u.get("last_login"),
                "license_key": _mask_key(raw_key),
                "tier": tier,
            }
        )

    total = len(all_items)
    start = (page - 1) * limit
    items = all_items[start : start + limit]
    pages = math.ceil(total / limit) if total > 0 else 1

    return JSONResponse(
        {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": pages,
        }
    )


@admin_router.get("/admin/licenses")
async def admin_licenses(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """Return paginated list of all licenses for admin only."""
    import json
    from pathlib import Path

    current_user = get_current_user(request)
    if not current_user or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    client_ip = get_client_ip(request)
    admin_limiter = getattr(request.app.state, "admin_limiter", None)
    if admin_limiter and not admin_limiter.is_allowed(client_ip):
        return JSONResponse({"error": "Rate limit exceeded. Try again later."}, status_code=429)

    licenses_path = Path(__file__).parent.parent / "data" / "licenses.json"
    if not licenses_path.exists():
        all_items: list = []
    else:
        with open(licenses_path, "r") as f:
            data = json.load(f)
        raw_licenses = data.get("licenses", [])
        all_items = []
        for lic in raw_licenses:
            key = lic.get("key", "")
            masked = key[:10] + "..." if len(key) > 10 else key
            all_items.append(
                {
                    "key": masked,
                    "tier": lic.get("tier", "community"),
                    "expires_at": lic.get("expires_at"),
                    "revoked": lic.get("revoked", False),
                    "created_at": lic.get("created_at"),
                    "stripe_customer_id": lic.get("stripe_customer_id"),
                    "stripe_subscription_id": lic.get("stripe_subscription_id"),
                    "billing_interval": lic.get("billing_interval"),
                    "max_activations": lic.get("max_activations"),
                    "current_activations": lic.get("current_activations", 0),
                }
            )

    total = len(all_items)
    start = (page - 1) * limit
    items = all_items[start : start + limit]
    pages = math.ceil(total / limit) if total > 0 else 1

    return JSONResponse(
        {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": pages,
        }
    )


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "auth_router", "admin_router", "get_current_user",
    "get_license_key_for_request", "generate_csrf_token",
    "validate_csrf_token",
]
