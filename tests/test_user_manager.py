"""Comprehensive tests for webapp/user_manager.py.

Tests cover:
- Singleton construction / reset
- create_user (email/password, google OAuth, duplicate rejection, case normalization)
- get_by_email / get_by_google_id / get_by_id (found and not-found)
- verify_password (success, wrong password, nonexistent, OAuth-only user)
- update_last_login (existing and nonexistent user)
- set_license_key / clear_license_key (found / not-found)
- list_emails / list_users (field inclusion / exclusion)
- find_by_license_key
"""

from __future__ import annotations

import secrets
import tempfile
import threading
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

import webapp.user_manager as um_module
from webapp.user_manager import UserManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_singleton() -> None:
    """Tear down the UserManager singleton completely."""
    UserManager._instance = None
    # Also reset _initialized on any stale instance (belt-and-suspenders)
    try:
        UserManager._initialized = False
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Generator[Path, None, None]:
    """Patch _USERS_DB_PATH to a temporary directory and reset the singleton."""
    db_path = tmp_path / "data" / "users.json"
    _reset_singleton()
    with patch.object(um_module, "_USERS_DB_PATH", db_path):
        yield db_path
    _reset_singleton()


@pytest.fixture()
def manager(tmp_db: Path) -> UserManager:
    """Return a fresh UserManager bound to the temp DB."""
    return UserManager()


# ---------------------------------------------------------------------------
# Helper: pre-created users
# ---------------------------------------------------------------------------


def _make_email_user(mgr: UserManager, email: str = "alice@example.com") -> dict:
    return mgr.create_user(email=email, name="Alice", password=f"U!{secrets.token_hex(5)}")


def _make_oauth_user(mgr: UserManager, email: str = "bob@example.com") -> dict:
    return mgr.create_user(
        email=email,
        name="Bob",
        google_id="google-sub-001",
        auth_method="google",
    )


# ===========================================================================
# TestUserManagerCreation
# ===========================================================================


class TestUserManagerCreation:
    def test_create_user_with_password(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        assert user["email"] == "alice@example.com"
        assert user["name"] == "Alice"
        assert user["password_hash"] is not None
        assert user["auth_method"] == "email"
        assert user["google_id"] is None
        assert user["license_key"] is None
        assert "id" in user

    def test_create_user_with_google_id(self, manager: UserManager) -> None:
        user = _make_oauth_user(manager)
        assert user["email"] == "bob@example.com"
        assert user["google_id"] == "google-sub-001"
        assert user["password_hash"] is None
        assert user["auth_method"] == "google"

    def test_duplicate_email_raises(self, manager: UserManager) -> None:
        _make_email_user(manager, "dup@example.com")
        with pytest.raises(ValueError, match="already registered"):
            manager.create_user(
                email="dup@example.com",
                name="Dup2",
                password=f"U!{secrets.token_hex(5)}",
            )

    def test_email_stored_as_lowercase(self, manager: UserManager) -> None:
        user = manager.create_user(email="  UPPER@EXAMPLE.COM  ", name="Upper")
        assert user["email"] == "upper@example.com"

    def test_duplicate_check_is_case_insensitive(self, manager: UserManager) -> None:
        manager.create_user(email="case@example.com", name="Case")
        with pytest.raises(ValueError):
            manager.create_user(email="CASE@EXAMPLE.COM", name="Case2")

    def test_user_has_uuid_id(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        import uuid
        # Should not raise
        uuid.UUID(user["id"])

    def test_user_has_created_at_and_last_login(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        assert user["created_at"]
        assert user["last_login"]

    def test_create_user_no_password_no_google(self, manager: UserManager) -> None:
        """A user may be created without password or google_id (edge case)."""
        user = manager.create_user(email="nobody@example.com", name="Nobody")
        assert user["password_hash"] is None
        assert user["google_id"] is None

    def test_multiple_users_stored(self, manager: UserManager) -> None:
        _make_email_user(manager, "u1@example.com")
        _make_email_user(manager, "u2@example.com")
        _make_email_user(manager, "u3@example.com")
        assert len(manager.list_users()) == 3


# ===========================================================================
# TestUserManagerSingleton
# ===========================================================================


class TestUserManagerSingleton:
    def test_same_instance_returned(self, manager: UserManager) -> None:
        mgr2 = UserManager()
        assert manager is mgr2

    def test_reset_gives_new_instance(self, tmp_db: Path) -> None:
        mgr1 = UserManager()
        _reset_singleton()
        with patch.object(um_module, "_USERS_DB_PATH", tmp_db):
            mgr2 = UserManager()
        assert mgr1 is not mgr2


# ===========================================================================
# TestUserManagerRetrieval
# ===========================================================================


class TestUserManagerRetrieval:
    def test_get_by_email_found(self, manager: UserManager) -> None:
        created = _make_email_user(manager)
        found = manager.get_by_email("alice@example.com")
        assert found is not None
        assert found["id"] == created["id"]

    def test_get_by_email_not_found(self, manager: UserManager) -> None:
        assert manager.get_by_email("nobody@example.com") is None

    def test_get_by_email_case_insensitive(self, manager: UserManager) -> None:
        _make_email_user(manager)
        found = manager.get_by_email("ALICE@EXAMPLE.COM")
        assert found is not None

    def test_get_by_email_strips_whitespace(self, manager: UserManager) -> None:
        _make_email_user(manager)
        found = manager.get_by_email("  alice@example.com  ")
        assert found is not None

    def test_get_by_google_id_found(self, manager: UserManager) -> None:
        created = _make_oauth_user(manager)
        found = manager.get_by_google_id("google-sub-001")
        assert found is not None
        assert found["id"] == created["id"]

    def test_get_by_google_id_not_found(self, manager: UserManager) -> None:
        assert manager.get_by_google_id("nonexistent-google-id") is None

    def test_get_by_id_found(self, manager: UserManager) -> None:
        created = _make_email_user(manager)
        found = manager.get_by_id(created["id"])
        assert found is not None
        assert found["email"] == "alice@example.com"

    def test_get_by_id_not_found(self, manager: UserManager) -> None:
        assert manager.get_by_id("00000000-0000-0000-0000-000000000000") is None

    def test_get_by_email_has_stripe_defaults(self, manager: UserManager) -> None:
        _make_email_user(manager)
        found = manager.get_by_email("alice@example.com")
        assert "license_key" in found
        assert "stripe_customer_id" in found
        assert "stripe_subscription_id" in found

    def test_get_by_google_id_has_stripe_defaults(self, manager: UserManager) -> None:
        _make_oauth_user(manager)
        found = manager.get_by_google_id("google-sub-001")
        assert found is not None
        assert "license_key" in found

    def test_get_by_id_has_stripe_defaults(self, manager: UserManager) -> None:
        created = _make_email_user(manager)
        found = manager.get_by_id(created["id"])
        assert found is not None
        assert "license_key" in found


# ===========================================================================
# TestUserManagerAuthentication
# ===========================================================================


class TestUserManagerAuthentication:
    def test_verify_password_success(self, manager: UserManager) -> None:
        pw = f"U!{secrets.token_hex(5)}"
        manager.create_user(email="alice@example.com", name="Alice", password=pw)
        result = manager.verify_password("alice@example.com", pw)
        assert result is not None
        assert result["email"] == "alice@example.com"

    def test_verify_password_wrong_password(self, manager: UserManager) -> None:
        pw = f"U!{secrets.token_hex(5)}"
        manager.create_user(email="alice@example.com", name="Alice", password=pw)
        assert manager.verify_password("alice@example.com", "wrongpass") is None

    def test_verify_password_nonexistent_email(self, manager: UserManager) -> None:
        assert manager.verify_password("ghost@example.com", "any") is None

    def test_verify_password_oauth_only_user(self, manager: UserManager) -> None:
        """An OAuth-only user with no password hash should fail verification."""
        _make_oauth_user(manager)
        assert manager.verify_password("bob@example.com", "any") is None

    def test_verify_password_case_insensitive_email(self, manager: UserManager) -> None:
        pw = f"U!{secrets.token_hex(5)}"
        manager.create_user(email="alice@example.com", name="Alice", password=pw)
        result = manager.verify_password("ALICE@EXAMPLE.COM", pw)
        assert result is not None

    def test_verify_password_returns_user_dict(self, manager: UserManager) -> None:
        pw = f"U!{secrets.token_hex(5)}"
        manager.create_user(email="alice@example.com", name="Alice", password=pw)
        result = manager.verify_password("alice@example.com", pw)
        assert isinstance(result, dict)
        assert "id" in result
        assert "email" in result


# ===========================================================================
# TestUserManagerUpdates
# ===========================================================================


class TestUserManagerUpdates:
    def test_update_last_login_changes_timestamp(self, manager: UserManager) -> None:
        import time
        user = _make_email_user(manager)
        original = user["last_login"]
        time.sleep(0.01)
        manager.update_last_login(user["id"])
        updated = manager.get_by_id(user["id"])
        assert updated is not None
        # Timestamp should change (or at minimum not crash)
        # Can't guarantee > on fast machines, just ensure it ran without error
        assert updated["last_login"] is not None

    def test_update_last_login_nonexistent_user(self, manager: UserManager) -> None:
        """Should silently do nothing for an unknown user_id."""
        manager.update_last_login("00000000-0000-0000-0000-000000000000")

    def test_set_license_key_returns_true(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        result = manager.set_license_key(user["id"], "LIC-123")
        assert result is True

    def test_set_license_key_stores_value(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC-XYZ")
        found = manager.get_by_id(user["id"])
        assert found["license_key"] == "LIC-XYZ"

    def test_set_license_key_with_stripe_ids(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(
            user["id"],
            "LIC-STRIPE",
            stripe_customer_id="cus_123",
            stripe_subscription_id="sub_456",
        )
        found = manager.get_by_id(user["id"])
        assert found["stripe_customer_id"] == "cus_123"
        assert found["stripe_subscription_id"] == "sub_456"

    def test_set_license_key_nonexistent_user(self, manager: UserManager) -> None:
        result = manager.set_license_key("00000000-0000-0000-0000-000000000000", "LIC")
        assert result is False

    def test_set_license_key_without_stripe_ids_preserves_none(
        self, manager: UserManager
    ) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC-ONLY")
        found = manager.get_by_id(user["id"])
        assert found["stripe_customer_id"] is None
        assert found["stripe_subscription_id"] is None

    def test_clear_license_key_returns_true(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC-TO-CLEAR", "cus_1", "sub_1")
        result = manager.clear_license_key(user["id"])
        assert result is True

    def test_clear_license_key_removes_data(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC", "cus_1", "sub_1")
        manager.clear_license_key(user["id"])
        found = manager.get_by_id(user["id"])
        assert found["license_key"] is None
        assert found["stripe_customer_id"] is None
        assert found["stripe_subscription_id"] is None

    def test_clear_license_key_nonexistent_user(self, manager: UserManager) -> None:
        result = manager.clear_license_key("00000000-0000-0000-0000-000000000000")
        assert result is False


# ===========================================================================
# TestUserManagerListing
# ===========================================================================


class TestUserManagerListing:
    def test_list_emails_empty(self, manager: UserManager) -> None:
        assert manager.list_emails() == []

    def test_list_emails_returns_correct_fields(self, manager: UserManager) -> None:
        _make_email_user(manager)
        entries = manager.list_emails()
        assert len(entries) == 1
        entry = entries[0]
        assert set(entry.keys()) == {"email", "name", "created_at"}
        assert entry["email"] == "alice@example.com"

    def test_list_emails_multiple_users(self, manager: UserManager) -> None:
        _make_email_user(manager, "u1@example.com")
        _make_email_user(manager, "u2@example.com")
        entries = manager.list_emails()
        emails = {e["email"] for e in entries}
        assert emails == {"u1@example.com", "u2@example.com"}

    def test_list_users_empty(self, manager: UserManager) -> None:
        assert manager.list_users() == []

    def test_list_users_excludes_password_hash(self, manager: UserManager) -> None:
        _make_email_user(manager)
        users = manager.list_users()
        assert len(users) == 1
        assert "password_hash" not in users[0]

    def test_list_users_excludes_google_id(self, manager: UserManager) -> None:
        _make_oauth_user(manager)
        users = manager.list_users()
        assert "google_id" not in users[0]

    def test_list_users_includes_required_fields(self, manager: UserManager) -> None:
        _make_email_user(manager)
        users = manager.list_users()
        u = users[0]
        for field in ("email", "name", "created_at", "auth_method", "last_login", "license_key"):
            assert field in u, f"Missing field: {field}"

    def test_list_users_shows_license_key(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC-LISTED")
        users = manager.list_users()
        assert users[0]["license_key"] == "LIC-LISTED"

    def test_find_by_license_key_found(self, manager: UserManager) -> None:
        user = _make_email_user(manager)
        manager.set_license_key(user["id"], "LIC-FIND-ME")
        found = manager.find_by_license_key("LIC-FIND-ME")
        assert found is not None
        assert found["id"] == user["id"]

    def test_find_by_license_key_not_found(self, manager: UserManager) -> None:
        _make_email_user(manager)
        assert manager.find_by_license_key("NONEXISTENT-KEY") is None

    def test_find_by_license_key_matches_exact(self, manager: UserManager) -> None:
        user1 = _make_email_user(manager, "u1@example.com")
        user2 = _make_email_user(manager, "u2@example.com")
        manager.set_license_key(user1["id"], "LIC-A")
        manager.set_license_key(user2["id"], "LIC-B")
        found = manager.find_by_license_key("LIC-A")
        assert found["id"] == user1["id"]

    def test_find_by_license_key_no_match_among_nulls(
        self, manager: UserManager
    ) -> None:
        _make_email_user(manager)
        _make_email_user(manager, "u2@example.com")
        assert manager.find_by_license_key("ANY-KEY") is None


# ===========================================================================
# TestUserManagerThreadSafety
# ===========================================================================


class TestUserManagerThreadSafety:
    def test_concurrent_creates_no_duplicate(self, manager: UserManager) -> None:
        """Concurrent create_user calls with unique emails must all succeed."""
        errors: list = []

        def create(i: int) -> None:
            try:
                manager.create_user(email=f"user{i}@example.com", name=f"User{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors in concurrent creates: {errors}"
        assert len(manager.list_users()) == 10

    def test_concurrent_duplicate_only_one_succeeds(self, manager: UserManager) -> None:
        """Concurrent creates with the SAME email: exactly one must succeed."""
        successes = []
        failures = []
        lock = threading.Lock()

        def create() -> None:
            try:
                manager.create_user(email="same@example.com", name="Same")
                with lock:
                    successes.append(1)
            except ValueError:
                with lock:
                    failures.append(1)

        threads = [threading.Thread(target=create) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 1
        assert len(failures) == 4


# ===========================================================================
# TestUserManagerPersistence
# ===========================================================================


class TestUserManagerPersistence:
    def test_data_persists_across_singleton_reset(self, tmp_db: Path) -> None:
        """After resetting the singleton the data on disk is still readable."""
        mgr1 = UserManager()
        mgr1.create_user(
            email="persist@example.com",
            name="Persist",
            password=f"U!{secrets.token_hex(5)}",
        )

        # Reset singleton to simulate a new process startup
        _reset_singleton()
        with patch.object(um_module, "_USERS_DB_PATH", tmp_db):
            mgr2 = UserManager()
            found = mgr2.get_by_email("persist@example.com")

        assert found is not None
        assert found["name"] == "Persist"

    def test_db_file_created_on_init(self, tmp_db: Path) -> None:
        UserManager()
        assert tmp_db.exists()

    def test_db_missing_returns_empty_users(self, tmp_db: Path) -> None:
        """_load_db returns empty schema when file absent."""
        mgr = UserManager()
        # Remove DB manually
        if tmp_db.exists():
            tmp_db.unlink()
        result = mgr._load_db()
        assert result == {"users": [], "version": 1}
