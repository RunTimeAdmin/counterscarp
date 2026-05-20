"""User manager module for Counterscarp Engine web application.

Provides a thread-safe JSON file backend for user persistence,
supporting both email/password and Google OAuth authentication.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import base64
import hashlib
import logging
import os

import bcrypt as _bcrypt
from cryptography.fernet import Fernet

from webapp.config import BASE_DIR, SESSION_SECRET

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USERS_DB_PATH: Path = BASE_DIR / "data" / "users.json"

_KNOWN_INSECURE_DEFAULT = "counterscarp-dev-session-secret-INSECURE-DEFAULT"


def _prepare_password_for_bcrypt(password: str) -> bytes:
    """Pre-hash password into a fixed-length bcrypt-safe byte string.

    bcrypt silently truncates inputs beyond 72 bytes. To preserve full password
    entropy for any input length, hash with SHA-256 and base64-encode
    the digest before bcrypt processing.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def _derive_fernet_key() -> bytes:
    """Derive a Fernet-compatible key for TOTP encryption.

    Priority:
      1. ``TOTP_ENCRYPTION_KEY`` env var (dedicated key — recommended)
      2. ``SESSION_SECRET`` (fallback with warning)

    A CRITICAL log is emitted when the key source is the hardcoded insecure
    default and no dedicated key has been configured.
    """
    totp_key_env = os.environ.get("TOTP_ENCRYPTION_KEY", "").strip()

    if totp_key_env:
        # Dedicated key provided — derive via SHA-256 just like the legacy path
        digest = hashlib.sha256(totp_key_env.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    # Fallback to SESSION_SECRET
    _logger.warning(
        "TOTP_ENCRYPTION_KEY not set — falling back to SESSION_SECRET. "
        "Set a dedicated key for production."
    )

    if SESSION_SECRET == _KNOWN_INSECURE_DEFAULT:
        _logger.critical(
            "TOTP encryption is using the hardcoded insecure default "
            "SESSION_SECRET. All TOTP secrets are trivially decryptable! "
            "Set TOTP_ENCRYPTION_KEY or a strong SESSION_SECRET immediately."
        )

    digest = hashlib.sha256(SESSION_SECRET.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_derive_fernet_key())


# ---------------------------------------------------------------------------
# UserManager
# ---------------------------------------------------------------------------


class UserManager:
    """Singleton user manager backed by data/users.json.

    All public methods are thread-safe via a single file-level lock.
    """

    _instance: Optional["UserManager"] = None
    _class_lock = threading.Lock()
    _initialized: bool

    # ------------------------------------------------------------------
    # Singleton construction
    # ------------------------------------------------------------------

    def __new__(cls) -> "UserManager":
        if cls._instance is None:
            with cls._class_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        with self._class_lock:
            if self._initialized:
                return
            self._file_lock = threading.Lock()
            self._cache: Optional[Dict[str, Any]] = None
            self._cache_mtime: float = 0.0
            self._ensure_db()
            self._initialized = True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_db(self) -> None:
        """Create data/users.json with an empty schema if it does not exist."""
        _USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not _USERS_DB_PATH.exists():
            self._write_db({"users": [], "version": 1})

    def _load_db(self) -> Dict[str, Any]:
        """Load the users database from disk with mtime caching."""
        try:
            mtime = _USERS_DB_PATH.stat().st_mtime
        except FileNotFoundError:
            return {"users": [], "version": 1}
        if self._cache is not None and mtime == self._cache_mtime:
            return self._cache
        with open(_USERS_DB_PATH, "r", encoding="utf-8") as f:
            self._cache = json.load(f)
        self._cache_mtime = mtime
        return self._cache

    def _write_db(self, db: Dict) -> None:
        """Persist the users database to disk."""
        _USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _USERS_DB_PATH.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        tmp.replace(_USERS_DB_PATH)
        self._cache = db
        self._cache_mtime = _USERS_DB_PATH.stat().st_mtime

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_user(
        self,
        email: str,
        name: str,
        password: Optional[str] = None,
        google_id: Optional[str] = None,
        auth_method: str = "email",
    ) -> Dict[str, Any]:
        """Create a new user and return the user dict.

        Args:
            email: User email address (stored and compared as lowercase).
            name: Display name.
            password: Plaintext password (hashed with bcrypt). May be None
                for OAuth-only accounts.
            google_id: Google subject identifier for OAuth users.
            auth_method: ``"email"`` or ``"google"``.

        Returns:
            The newly created user dict.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        email = email.strip().lower()

        with self._file_lock:
            db = self._load_db()

            # Uniqueness check
            for existing_user in db["users"]:
                if existing_user["email"] == email:
                    raise ValueError(f"Email already registered: {email}")

            now = datetime.now(timezone.utc).isoformat()
            password_hash = (
                _bcrypt.hashpw(
                    _prepare_password_for_bcrypt(password),
                    _bcrypt.gensalt(),
                ).decode("utf-8")
                if password
                else None
            )
            user: Dict[str, Any] = {
                "id": str(uuid.uuid4()),
                "email": email,
                "name": name,
                "google_id": google_id,
                "password_hash": password_hash,
                "created_at": now,
                "last_login": now,
                "auth_method": auth_method,
                "license_key": None,
                "stripe_customer_id": None,
                "stripe_subscription_id": None,
                "scan_credits": 0,
                "credits_used": 0,
            }

            db["users"].append(user)
            self._write_db(db)

        return user

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Return the user dict for *email*, or None if not found."""
        email = email.strip().lower()
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["email"] == email:
                    user.setdefault("license_key", None)
                    user.setdefault("stripe_customer_id", None)
                    user.setdefault("stripe_subscription_id", None)
                    user.setdefault("totp_secret", "")
                    user.setdefault("totp_enabled", False)
                    user.setdefault("scan_credits", 0)
                    user.setdefault("credits_used", 0)
                    return dict(user)
        return None

    def get_by_google_id(self, google_id: str) -> Optional[Dict[str, Any]]:
        """Return the user dict for *google_id*, or None if not found."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user.get("google_id") == google_id:
                    user.setdefault("license_key", None)
                    user.setdefault("stripe_customer_id", None)
                    user.setdefault("stripe_subscription_id", None)
                    user.setdefault("totp_secret", "")
                    user.setdefault("totp_enabled", False)
                    user.setdefault("scan_credits", 0)
                    user.setdefault("credits_used", 0)
                    return dict(user)
        return None

    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Return the user dict for *user_id*, or None if not found."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user.setdefault("license_key", None)
                    user.setdefault("stripe_customer_id", None)
                    user.setdefault("stripe_subscription_id", None)
                    user.setdefault("totp_secret", "")
                    user.setdefault("totp_enabled", False)
                    user.setdefault("scan_credits", 0)
                    user.setdefault("credits_used", 0)
                    return dict(user)
        return None

    def verify_password(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify *password* against the stored hash for *email*.

        Returns:
            The user dict on success, or ``None`` if the email doesn't exist,
            has no password hash, or the password is wrong.
        """
        user = self.get_by_email(email)
        if user is None:
            return None
        stored_hash = user.get("password_hash")
        if not stored_hash:
            return None
        try:
            valid = _bcrypt.checkpw(
                _prepare_password_for_bcrypt(password),
                stored_hash.encode("utf-8"),
            )
        except Exception:
            return None
        return user if valid else None

    def update_last_login(self, user_id: str) -> None:
        """Update the ``last_login`` timestamp for *user_id* to now (UTC)."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["last_login"] = datetime.now(timezone.utc).isoformat()
                    break
            self._write_db(db)

    def list_emails(self) -> List[Dict]:
        """Return a list of dicts with ``email``, ``name``, and ``created_at``.

        Suitable for mailing list export.
        """
        with self._file_lock:
            db = self._load_db()
            return [
                {
                    "email": u["email"],
                    "name": u["name"],
                    "created_at": u["created_at"],
                }
                for u in db["users"]
            ]

    def set_license_key(
        self,
        user_id: str,
        license_key: str,
        stripe_customer_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
    ) -> bool:
        """Attach a license key (and optional Stripe IDs) to a user.

        Args:
            user_id: The user's UUID.
            license_key: The license key string to store.
            stripe_customer_id: Optional Stripe customer ID.
            stripe_subscription_id: Optional Stripe subscription ID.

        Returns:
            True if the user was found and updated, False otherwise.
        """
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["license_key"] = license_key
                    if stripe_customer_id is not None:
                        user["stripe_customer_id"] = stripe_customer_id
                    if stripe_subscription_id is not None:
                        user["stripe_subscription_id"] = stripe_subscription_id
                    self._write_db(db)
                    return True
        return False

    def clear_license_key(self, user_id: str) -> bool:
        """Remove the license key and Stripe IDs from a user.

        Args:
            user_id: The user's UUID.

        Returns:
            True if the user was found and updated, False otherwise.
        """
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["license_key"] = None
                    user["stripe_customer_id"] = None
                    user["stripe_subscription_id"] = None
                    self._write_db(db)
                    return True
        return False

    def list_users(self) -> List[Dict]:
        """Return all users without sensitive fields.

        Each entry includes: email, name, created_at, auth_method, last_login,
        license_key, stripe_customer_id, stripe_subscription_id.
        ``password_hash`` and ``google_id`` are excluded for security.
        """
        with self._file_lock:
            db = self._load_db()
            result = []
            for u in db["users"]:
                u.setdefault("auth_method", "email")
                u.setdefault("last_login", u.get("created_at"))
                u.setdefault("license_key", None)
                u.setdefault("stripe_customer_id", None)
                u.setdefault("stripe_subscription_id", None)
                result.append(
                    {
                        "email": u["email"],
                        "name": u["name"],
                        "created_at": u["created_at"],
                        "auth_method": u["auth_method"],
                        "last_login": u["last_login"],
                        "license_key": u["license_key"],
                    }
                )
            return result

    def find_by_license_key(
        self, license_key: str,
    ) -> Optional[Dict[str, Any]]:
        """Return the user dict whose ``license_key`` matches, or None.

        Useful for checking whether a license key is already linked to an
        existing account.

        Args:
            license_key: The license key to search for.

        Returns:
            The matching user dict, or None if no match is found.
        """
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user.get("license_key") == license_key:
                    return dict(user)
        return None

    # ------------------------------------------------------------------
    # TOTP two-factor authentication
    # ------------------------------------------------------------------

    def enable_totp(self, user_id: str, secret: str) -> None:
        """Store an encrypted TOTP secret and enable 2FA for the user."""
        encrypted = _fernet.encrypt(
            secret.encode("utf-8")
        ).decode("utf-8")
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["totp_secret"] = encrypted
                    user["totp_enabled"] = True
                    self._write_db(db)
                    return

    def disable_totp(self, user_id: str) -> None:
        """Clear TOTP secret and disable 2FA for the user."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["totp_secret"] = ""
                    user["totp_enabled"] = False
                    self._write_db(db)
                    return

    def get_totp_secret(
        self, user_id: str,
    ) -> Optional[str]:
        """Return the decrypted TOTP secret, or None."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    enc = user.get("totp_secret", "")
                    if not enc:
                        return None
                    try:
                        return _fernet.decrypt(
                            enc.encode("utf-8")
                        ).decode("utf-8")
                    except Exception:
                        return None
        return None

    # ------------------------------------------------------------------
    # TOTP recovery codes
    # ------------------------------------------------------------------

    def set_recovery_codes(self, user_id: str, codes_hashed: List[str]) -> None:
        """Store hashed recovery codes for a user."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["recovery_codes"] = codes_hashed
                    self._write_db(db)
                    return

    def use_recovery_code(self, user_id: str, code: str) -> bool:
        """Verify and consume a one-time recovery code.

        Returns True if the code matched (and was removed), False otherwise.
        """
        code_hash = hashlib.sha256(
            code.strip().encode("utf-8")
        ).hexdigest()
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    stored: List[str] = user.get("recovery_codes", [])
                    if code_hash in stored:
                        stored.remove(code_hash)
                        user["recovery_codes"] = stored
                        self._write_db(db)
                        return True
                    return False
        return False

    # ------------------------------------------------------------------
    # Notification email
    # ------------------------------------------------------------------

    def set_notification_email(self, user_id: str, email: str) -> bool:
        """Set the notification email for a user.

        Returns True if the user was found and updated.
        """
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    user["notification_email"] = email
                    self._write_db(db)
                    return True
        return False

    def get_notification_email(self, user_id: str) -> Optional[str]:
        """Return the notification email for *user_id*, or None."""
        with self._file_lock:
            db = self._load_db()
            for user in db["users"]:
                if user["id"] == user_id:
                    return user.get("notification_email") or None
        return None

    # ------------------------------------------------------------------
    # Scan credits (PAYG)
    # ------------------------------------------------------------------

    def get_scan_credits(self, user_id: str) -> int:
        """Return the number of remaining scan credits for a user."""
        user = self.get_by_id(user_id)
        if not user:
            return 0
        return int(user.get("scan_credits", 0))

    def set_scan_credits(self, user_id: str, credits: int) -> None:
        """Set the scan credit balance for a user (overwrites)."""
        with self._file_lock:
            db = self._load_db()
            for u in db.get("users", []):
                if u["id"] == user_id:
                    u["scan_credits"] = credits
                    self._write_db(db)
                    return

    def add_scan_credits(self, user_id: str, delta: int) -> int:
        """Atomically add scan credits and return new balance. Holds lock for full operation."""
        with self._file_lock:
            db = self._load_db()
            for u in db.get("users", []):
                if u["id"] == user_id:
                    current = u.get("scan_credits", 0)
                    new_balance = current + delta
                    u["scan_credits"] = new_balance
                    self._write_db(db)
                    return int(new_balance)
        return 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

user_manager = UserManager()
