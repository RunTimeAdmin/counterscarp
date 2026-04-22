"""Configuration for the Counterscarp Engine web application."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
RESULTS_DIR = BASE_DIR / "results"
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
LOGO_PATH = BASE_DIR / "assets" / "logo_small.png"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {".sol", ".rs"}

# Deployment environment — set to "production" to enforce strict secret validation
COUNTERSCARP_ENV = os.environ.get("COUNTERSCARP_ENV", "development")

# Authentication
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
if not SESSION_SECRET:
    if COUNTERSCARP_ENV == "production":
        raise RuntimeError(
            "SESSION_SECRET environment variable is required in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    import warnings
    warnings.warn(
        "SESSION_SECRET not set — using insecure default. "
        "Set SESSION_SECRET env var in production. "
        "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"",
        stacklevel=2,
    )
    SESSION_SECRET = "counterscarp-dev-session-secret-INSECURE-DEFAULT"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8001/auth/google/callback")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")


def validate_production_config() -> None:
    """Validate all required secrets are set for production deployment."""
    if COUNTERSCARP_ENV != "production":
        return
    missing = []
    if not SESSION_SECRET or SESSION_SECRET == "counterscarp-dev-session-secret-INSECURE-DEFAULT":
        missing.append("SESSION_SECRET")
    if not os.environ.get("STRIPE_SECRET_KEY"):
        missing.append("STRIPE_SECRET_KEY")
    if not os.environ.get("STRIPE_WEBHOOK_SECRET"):
        missing.append("STRIPE_WEBHOOK_SECRET")
    if not os.environ.get("GOOGLE_CLIENT_ID"):
        missing.append("GOOGLE_CLIENT_ID")
    if missing:
        raise RuntimeError(
            f"Missing required secrets for production: {', '.join(missing)}. "
            "Set these environment variables before starting in production mode."
        )
