"""Authentication routes for Counterscarp Engine web application.

Provides email/password and Google OAuth login, registration, logout,
and an admin endpoint for mailing-list export.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import math
import secrets
import string
import time

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer
from starlette.templating import Jinja2Templates

from webapp.user_manager import user_manager
from webapp.rate_limiter import get_client_ip, add_rate_limit_headers
from webapp.license_api import link_license_to_user
from webapp.config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    ADMIN_EMAIL,
    TEMPLATES_DIR,
    SESSION_SECRET,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM,
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
_password_reset_serializer = URLSafeTimedSerializer(
    SESSION_SECRET,
    salt="password-reset",
)


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


def _send_password_reset_email(recipient: str, reset_link: str) -> None:
    """Send password reset email if SMTP is configured."""
    if not SMTP_HOST:
        logger.warning(
            "SMTP_HOST not configured; password reset email skipped for %s",
            recipient,
        )
        return
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset your Counterscarp password"
    msg["From"] = SMTP_FROM or SMTP_USER or "noreply@counterscarp.io"
    msg["To"] = recipient
    html = (
        "<p>We received a password reset request for your Counterscarp account.</p>"
        f"<p><a href=\"{reset_link}\">Reset your password</a></p>"
        "<p>This link expires in 60 minutes. If you did not request this, you can ignore this email.</p>"
    )
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT or 587)) as server:
        server.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(msg["From"], [recipient], msg.as_string())


def get_current_user(request: Request):
    """Read session cookie and return user dict or None."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return user_manager.get_by_id(user_id)


def require_user(request: Request) -> dict:
    """FastAPI dependency — returns the current user or raises 401/redirect.

    Usage::

        @app.get("/protected")
        async def protected(current_user: dict = Depends(require_user)):
            ...

    Raises ``HTTPException(401)`` for API routes (path starts with ``/api/``),
    and returns a ``RedirectResponse`` for browser routes.
    """
    user = get_current_user(request)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(
            status_code=302,
            headers={"Location": "/auth/login"},
        )
    return user


def csrf_guard(request: Request, form_token: str) -> None:
    """Validate CSRF token from a submitted form, raising 403 on failure.

    Usage::

        form = await request.form()
        csrf_guard(request, str(form.get("_csrf_token", "")))

    Always validates — a missing or mismatched token is rejected.
    """
    if not validate_csrf_token(request, form_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


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
    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    client_ip = get_client_ip(request)
    login_limiter = getattr(request.app.state, "login_limiter", None)
    if login_limiter and not login_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Too many login attempts. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, login_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            login_limiter.get_reset_time(client_ip)
        )
        return resp_429
    user = user_manager.verify_password(email, password)
    if user:
        # Check if admin with TOTP enabled — require 2FA challenge
        is_admin = (
            ADMIN_EMAIL
            and user["email"] == ADMIN_EMAIL
        )
        totp_on = user.get("totp_enabled", False)
        if is_admin and totp_on:
            request.session["pending_2fa"] = user["id"]
            request.session["pending_2fa_expires"] = time.time() + 1800
            request.session["totp_attempts"] = 0
            resp = RedirectResponse(
                url="/auth/totp/verify", status_code=302,
            )
            if login_limiter:
                add_rate_limit_headers(
                    resp, login_limiter, client_ip,
                )
            return resp

        # Normal login — no 2FA needed
        request.session["user_id"] = user["id"]
        user_manager.update_last_login(user["id"])
        # Store user's license in the session (never in os.environ)
        if user.get("license_key"):
            request.session["user_license"] = user["license_key"]
        resp = RedirectResponse(url="/", status_code=302)
        if login_limiter:
            add_rate_limit_headers(resp, login_limiter, client_ip)
        return resp
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


@auth_router.get("/forgot-password")
async def forgot_password_page(request: Request):
    """Render forgot-password page."""
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        context={
            "current_user": None,
            "error": "",
            "message": "",
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.post("/forgot-password")
async def forgot_password_submit(
    request: Request,
    email: str = Form(...),
):
    """Handle forgot-password form without leaking account existence."""
    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    user = user_manager.get_by_email(email)
    if user:
        token = _password_reset_serializer.dumps(
            {"uid": user["id"], "purpose": "password-reset"}
        )
        reset_link = str(request.url_for("reset_password_page")) + f"?token={token}"
        try:
            _send_password_reset_email(user["email"], reset_link)
        except Exception as exc:  # pragma: no cover - external transport failure
            logger.warning("Password reset email send failed: %s", exc)

    # Generic message to prevent user enumeration.
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        context={
            "current_user": None,
            "error": "",
            "message": (
                "If an account exists for that email, a reset link has been sent."
            ),
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.get("/reset-password", name="reset_password_page")
async def reset_password_page(
    request: Request,
    token: str = Query(""),
):
    """Render reset-password page for a valid token."""
    error = ""
    token_valid = True
    if not token:
        token_valid = False
        error = "Reset link is missing or invalid."
    else:
        try:
            payload = _password_reset_serializer.loads(token, max_age=3600)
            if payload.get("purpose") != "password-reset" or not payload.get("uid"):
                token_valid = False
                error = "Reset link is invalid."
        except Exception:
            token_valid = False
            error = "Reset link is invalid or expired."

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        context={
            "current_user": None,
            "error": error,
            "success": "",
            "token": token,
            "token_valid": token_valid,
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.post("/reset-password")
async def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Reset password using a signed, time-limited token."""
    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    try:
        payload = _password_reset_serializer.loads(token, max_age=3600)
        if payload.get("purpose") != "password-reset" or not payload.get("uid"):
            raise ValueError("invalid payload")
        user_id = payload["uid"]
    except Exception:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            context={
                "current_user": None,
                "error": "Reset link is invalid or expired.",
                "success": "",
                "token": token,
                "token_valid": False,
                "csrf_token": generate_csrf_token(request),
            },
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            context={
                "current_user": None,
                "error": "Passwords do not match.",
                "success": "",
                "token": token,
                "token_valid": True,
                "csrf_token": generate_csrf_token(request),
            },
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            context={
                "current_user": None,
                "error": "Password must be at least 8 characters.",
                "success": "",
                "token": token,
                "token_valid": True,
                "csrf_token": generate_csrf_token(request),
            },
        )

    if not user_manager.set_password(user_id, password):
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            context={
                "current_user": None,
                "error": "Unable to reset password for this account.",
                "success": "",
                "token": token,
                "token_valid": False,
                "csrf_token": generate_csrf_token(request),
            },
        )

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        context={
            "current_user": None,
            "error": "",
            "success": "Password updated successfully. You can now sign in.",
            "token": "",
            "token_valid": False,
            "csrf_token": generate_csrf_token(request),
        },
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
    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    client_ip = get_client_ip(request)
    register_limiter = getattr(
        request.app.state, "register_limiter", None,
    )
    if register_limiter and not register_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Too many registration attempts. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(
            resp_429, register_limiter, client_ip,
        )
        resp_429.headers["Retry-After"] = str(
            register_limiter.get_reset_time(client_ip)
        )
        return resp_429
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

    resp = RedirectResponse(url="/", status_code=302)
    if register_limiter:
        add_rate_limit_headers(resp, register_limiter, client_ip)
    return resp


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
# TOTP two-factor authentication routes
# ---------------------------------------------------------------------------


@auth_router.get("/totp/setup")
async def totp_setup_page(request: Request):
    """Show TOTP enrollment page (admin-only, requires authentication)."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(
            url="/auth/login", status_code=302,
        )

    # TOTP 2FA is only available for admin accounts
    if not ADMIN_EMAIL or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse(
            {"error": "TOTP two-factor authentication is only available for admin accounts"},
            status_code=403,
        )

    secret = pyotp.random_base32()
    request.session["pending_totp_secret"] = secret

    totp = pyotp.totp.TOTP(secret)
    prov_uri = totp.provisioning_uri(
        current_user["email"],
        issuer_name="Counterscarp",
    )

    return templates.TemplateResponse(
        request,
        "totp_setup.html",
        context={
            "current_user": current_user,
            "provisioning_uri": prov_uri,
            "totp_secret": secret,
            "error": "",
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.post("/totp/setup")
async def totp_setup_submit(
    request: Request,
    code: str = Form(...),
):
    """Verify the TOTP code and enable 2FA for the user (admin-only)."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(
            url="/auth/login", status_code=302,
        )

    # TOTP 2FA is only available for admin accounts
    if not ADMIN_EMAIL or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse(
            {"error": "TOTP two-factor authentication is only available for admin accounts"},
            status_code=403,
        )

    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    secret = request.session.get("pending_totp_secret", "")
    if not secret:
        return RedirectResponse(
            url="/auth/totp/setup", status_code=302,
        )

    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        user_manager.enable_totp(
            current_user["id"], secret,
        )
        request.session.pop("pending_totp_secret", None)

        # Generate 10 one-time recovery codes
        _alphabet = string.ascii_lowercase + string.digits
        recovery_codes = [
            "".join(secrets.choice(_alphabet) for _ in range(8))
            for _ in range(10)
        ]
        codes_hashed = [
            hashlib.sha256(c.encode("utf-8")).hexdigest()
            for c in recovery_codes
        ]
        user_manager.set_recovery_codes(current_user["id"], codes_hashed)

        return templates.TemplateResponse(
            request,
            "totp_setup.html",
            context={
                "current_user": current_user,
                "provisioning_uri": "",
                "totp_secret": "",
                "error": "",
                "csrf_token": "",
                "setup_complete": True,
                "recovery_codes": recovery_codes,
            },
        )

    # Invalid code — re-render with error
    prov_uri = totp.provisioning_uri(
        current_user["email"],
        issuer_name="Counterscarp",
    )
    return templates.TemplateResponse(
        request,
        "totp_setup.html",
        context={
            "current_user": current_user,
            "provisioning_uri": prov_uri,
            "totp_secret": secret,
            "error": "Invalid code. Please try again.",
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.get("/totp/verify")
async def totp_verify_page(request: Request):
    """Show the TOTP challenge page during login."""
    pending = request.session.get("pending_2fa")
    if not pending:
        return RedirectResponse(
            url="/auth/login", status_code=302,
        )
    # Check expiry
    expires_at = request.session.get("pending_2fa_expires", 0)
    if time.time() > expires_at:
        request.session.pop("pending_2fa", None)
        request.session.pop("pending_2fa_expires", None)
        request.session.pop("totp_attempts", None)
        return RedirectResponse(
            url="/auth/login?error=2FA+session+expired.+Please+log+in+again.",
            status_code=302,
        )
    return templates.TemplateResponse(
        request,
        "totp_challenge.html",
        context={
            "current_user": None,
            "error": "",
            "csrf_token": generate_csrf_token(request),
        },
    )


@auth_router.post("/totp/verify")
async def totp_verify_submit(
    request: Request,
    code: str = Form(...),
):
    """Verify the 6-digit TOTP code during login."""
    form = await request.form()
    if not validate_csrf_token(request, str(form.get("_csrf_token", ""))):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    # --- Rate limiting (IP-based, reuse app-level limiter pattern) ---
    client_ip = get_client_ip(request)
    totp_limiter = getattr(request.app.state, "totp_limiter", None)
    if totp_limiter and not totp_limiter.is_allowed(client_ip):
        # After 10 consecutive failures by IP, enforce cooldown
        resp_429 = JSONResponse(
            {"detail": "Too many TOTP attempts. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, totp_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            totp_limiter.get_reset_time(client_ip)
        )
        return resp_429

    user_id = request.session.get("pending_2fa")
    if not user_id:
        return RedirectResponse(
            url="/auth/login", status_code=302,
        )

    # --- Expiry check (30 min window) ---
    expires_at = request.session.get("pending_2fa_expires", 0)
    if time.time() > expires_at:
        request.session.pop("pending_2fa", None)
        request.session.pop("pending_2fa_expires", None)
        request.session.pop("totp_attempts", None)
        return RedirectResponse(
            url="/auth/login?error=2FA+session+expired.+Please+log+in+again.",
            status_code=302,
        )

    secret = user_manager.get_totp_secret(user_id)
    if not secret:
        # TOTP was disabled between login and now
        request.session.pop("pending_2fa", None)
        return RedirectResponse(
            url="/auth/login", status_code=302,
        )

    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        # Complete authentication — reset attempt counters
        user = user_manager.get_by_id(user_id)
        if user:
            request.session["user_id"] = user["id"]
            user_manager.update_last_login(user["id"])
            if user.get("license_key"):
                request.session["user_license"] = (
                    user["license_key"]
                )
            request.session["totp_verified"] = True
        request.session.pop("pending_2fa", None)
        request.session.pop("pending_2fa_expires", None)
        request.session.pop("totp_attempts", None)
        return RedirectResponse(url="/", status_code=302)

    # --- Recovery code fallback ---
    if user_manager.use_recovery_code(user_id, code):
        user = user_manager.get_by_id(user_id)
        if user:
            request.session["user_id"] = user["id"]
            user_manager.update_last_login(user["id"])
            if user.get("license_key"):
                request.session["user_license"] = user["license_key"]
            request.session["totp_verified"] = True
        request.session.pop("pending_2fa", None)
        request.session.pop("pending_2fa_expires", None)
        request.session.pop("totp_attempts", None)
        return RedirectResponse(url="/", status_code=302)

    # --- Session-level attempt tracking ---
    attempts = request.session.get("totp_attempts", 0) + 1
    request.session["totp_attempts"] = attempts

    if attempts >= 5:
        # Invalidate pending 2FA after 5 failed attempts in this session
        request.session.pop("pending_2fa", None)
        request.session.pop("pending_2fa_expires", None)
        request.session.pop("totp_attempts", None)
        return RedirectResponse(
            url="/auth/login?error=Too+many+failed+2FA+attempts.+Please+log+in+again.",
            status_code=302,
        )

    # Invalid code
    return templates.TemplateResponse(
        request,
        "totp_challenge.html",
        context={
            "current_user": None,
            "error": "Invalid code. Please try again.",
            "csrf_token": generate_csrf_token(request),
        },
    )


# ---------------------------------------------------------------------------
# TOTP guard for admin endpoints
# ---------------------------------------------------------------------------


def _require_totp_or_redirect(
    request: Request,
) -> RedirectResponse | None:
    """If the current admin has TOTP enabled but has not verified
    this session, return a redirect response; otherwise None."""
    current_user = get_current_user(request)
    if not current_user:
        return None
    if current_user["email"] != ADMIN_EMAIL:
        return None
    if not current_user.get("totp_enabled", False):
        return None
    if request.session.get("totp_verified"):
        return None
    return RedirectResponse(
        url="/auth/totp/verify", status_code=302,
    )


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

    # TOTP guard for admin
    totp_redirect = _require_totp_or_redirect(request)
    if totp_redirect:
        return totp_redirect

    current_user = get_current_user(request)
    if not current_user or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    client_ip = get_client_ip(request)
    admin_limiter = getattr(
        request.app.state, "admin_limiter", None,
    )
    if admin_limiter and not admin_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"error": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, admin_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            admin_limiter.get_reset_time(client_ip)
        )
        return resp_429

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

    resp = JSONResponse(
        {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": pages,
        }
    )
    if admin_limiter:
        add_rate_limit_headers(resp, admin_limiter, client_ip)
    return resp


@admin_router.get("/admin/licenses")
async def admin_licenses(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """Return paginated list of all licenses for admin only."""
    import json
    from pathlib import Path

    # TOTP guard for admin
    totp_redirect = _require_totp_or_redirect(request)
    if totp_redirect:
        return totp_redirect

    current_user = get_current_user(request)
    if not current_user or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    client_ip = get_client_ip(request)
    admin_limiter = getattr(
        request.app.state, "admin_limiter", None,
    )
    if admin_limiter and not admin_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"error": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, admin_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            admin_limiter.get_reset_time(client_ip)
        )
        return resp_429

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

    resp = JSONResponse(
        {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": pages,
        }
    )
    if admin_limiter:
        add_rate_limit_headers(resp, admin_limiter, client_ip)
    return resp


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "auth_router", "admin_router", "get_current_user",
    "get_license_key_for_request", "generate_csrf_token",
    "validate_csrf_token", "_require_totp_or_redirect",
]
