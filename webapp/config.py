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
FREE_TOOL_MODE = os.environ.get("FREE_TOOL_MODE", "1").lower() in ("1", "true", "yes", "on")

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

# SMTP / notification settings
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = os.environ.get("SMTP_PORT", "587")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
NOTIFICATIONS_ENABLED = os.environ.get("NOTIFICATIONS_ENABLED", "").lower() in ("1", "true", "yes")


def validate_production_config() -> None:
    """Validate all required secrets are set for production deployment."""
    if COUNTERSCARP_ENV != "production":
        return
    if FREE_TOOL_MODE:
        import logging
        logging.getLogger("counterscarp.config").warning(
            "FREE_TOOL_MODE is enabled in production — payment enforcement is disabled."
        )
    missing = []
    if not SESSION_SECRET or SESSION_SECRET == "counterscarp-dev-session-secret-INSECURE-DEFAULT":
        missing.append("SESSION_SECRET")
    if not FREE_TOOL_MODE:
        if not os.environ.get("STRIPE_SECRET_KEY"):
            missing.append("STRIPE_SECRET_KEY")
        if not os.environ.get("STRIPE_WEBHOOK_SECRET"):
            missing.append("STRIPE_WEBHOOK_SECRET")
    if not os.environ.get("GOOGLE_CLIENT_ID"):
        missing.append("GOOGLE_CLIENT_ID")
    # If Stripe is configured, warn about missing PAYG price IDs (non-fatal)
    if (not FREE_TOOL_MODE) and os.environ.get("STRIPE_SECRET_KEY"):
        payg_missing = []
        for payg_var in (
            "STRIPE_PAYG_STARTER_PRICE_ID",
            "STRIPE_PAYG_STANDARD_PRICE_ID",
            "STRIPE_PAYG_PRO_PACK_PRICE_ID",
        ):
            if not os.environ.get(payg_var):
                payg_missing.append(payg_var)
        if payg_missing:
            import logging
            logging.getLogger("counterscarp.config").warning(
                "PAYG price IDs not configured: %s. "
                "PAYG checkout will fail until these are set.",
                ", ".join(payg_missing),
            )
    # TOTP encryption key is always required in production
    if not os.environ.get("TOTP_ENCRYPTION_KEY"):
        missing.append("TOTP_ENCRYPTION_KEY")
    if missing:
        raise RuntimeError(
            f"Missing required secrets for production: {', '.join(missing)}. "
            "Set these environment variables before starting in production mode."
        )

# PAYG credit pack configuration
PAYG_CREDITS_EXPIRY_DAYS = int(os.environ.get("PAYG_CREDITS_EXPIRY_DAYS", "365"))

# Machine-facing API keys (comma-separated ``label:secret`` pairs)
# Generate: python -c "import secrets; print('cs_' + secrets.token_urlsafe(32))"
COUNTERSCARP_API_KEYS = os.environ.get("COUNTERSCARP_API_KEYS", "")
