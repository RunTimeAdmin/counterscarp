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

# Authentication
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
if not SESSION_SECRET:
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
