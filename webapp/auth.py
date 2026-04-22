"""Authentication routes for Counterscarp Engine web application.

Provides email/password and Google OAuth login, registration, logout,
and an admin endpoint for mailing-list export.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from webapp.user_manager import user_manager
from webapp.config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    ADMIN_EMAIL,
    TEMPLATES_DIR,
)

# ---------------------------------------------------------------------------
# Router setup
# ---------------------------------------------------------------------------

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


def get_current_user(request: Request):
    """Read session cookie and return user dict or None."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return user_manager.get_by_id(user_id)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@auth_router.get("/login")
async def login_page(request: Request):
    """Render the login page."""
    error = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request, "login.html", context={"current_user": None, "error": error}
    )


@auth_router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    """Handle email/password login form submission."""
    user = user_manager.verify_password(email, password)
    if user:
        request.session["user_id"] = user["id"]
        user_manager.update_last_login(user["id"])
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
        request, "register.html", context={"current_user": None, "error": error}
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

        request.session["user_id"] = user["id"]
        user_manager.update_last_login(user["id"])
        return RedirectResponse(url="/", status_code=302)

    except Exception as exc:  # pylint: disable=broad-except
        error_msg = f"Google sign-in failed: {exc}"
        return RedirectResponse(
            url=f"/auth/login?error={error_msg.replace(' ', '+')}",
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
async def admin_users(request: Request):
    """Return mailing list for admin only."""
    current_user = get_current_user(request)
    if not current_user or current_user["email"] != ADMIN_EMAIL:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    return JSONResponse({"users": user_manager.list_emails()})


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = ["auth_router", "admin_router", "get_current_user"]
