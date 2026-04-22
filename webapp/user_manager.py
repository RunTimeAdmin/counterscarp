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
from typing import Dict, List, Optional

from passlib.hash import bcrypt

from webapp.config import BASE_DIR

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USERS_DB_PATH: Path = BASE_DIR / "data" / "users.json"


# ---------------------------------------------------------------------------
# UserManager
# ---------------------------------------------------------------------------


class UserManager:
    """Singleton user manager backed by data/users.json.

    All public methods are thread-safe via a single file-level lock.
    """

    _instance: Optional["UserManager"] = None
    _class_lock = threading.Lock()

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
        if self._initialized:  # type: ignore[has-type]
            return
        with self._class_lock:
            if self._initialized:
                return
            self._file_lock = threading.Lock()
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

    def _load_db(self) -> Dict:
        """Load the users database from disk."""
        if not _USERS_DB_PATH.exists():
            return {"users": [], "version": 1}
        with open(_USERS_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_db(self, db: Dict) -> None:
        """Persist the users database to disk."""
        _USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_USERS_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)

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
    ) -> Dict:
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
            for user in db["users"]:
                if user["email"] == email:
                    raise ValueError(f"Email already registered: {email}")

            now = datetime.now(timezone.utc).isoformat()
            user: Dict = {
                "id": str(uuid.uuid4()),
                "email": email,
                "name": name,
                "google_id": google_id,
                "password_hash": bcrypt.hash(password) if password else None,
                "created_at": now,
                "last_login": now,
                "auth_method": auth_method,
            }

            db["users"].append(user)
            self._write_db(db)

        return user

    def get_by_email(self, email: str) -> Optional[Dict]:
        """Return the user dict for *email*, or None if not found."""
        email = email.strip().lower()
        with self._file_lock:
            db = self._load_db()
        for user in db["users"]:
            if user["email"] == email:
                return user
        return None

    def get_by_google_id(self, google_id: str) -> Optional[Dict]:
        """Return the user dict for *google_id*, or None if not found."""
        with self._file_lock:
            db = self._load_db()
        for user in db["users"]:
            if user.get("google_id") == google_id:
                return user
        return None

    def get_by_id(self, user_id: str) -> Optional[Dict]:
        """Return the user dict for *user_id*, or None if not found."""
        with self._file_lock:
            db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                return user
        return None

    def verify_password(self, email: str, password: str) -> Optional[Dict]:
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
            valid = bcrypt.verify(password, stored_hash)
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


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

user_manager = UserManager()
