"""Tests for PAYG credit pack feature — credit management and consumption."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Generator
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

import webapp.user_manager as um_module
from webapp.user_manager import UserManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_singleton() -> None:
    """Tear down the UserManager singleton completely."""
    UserManager._instance = None
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


def _seed_users(db_path: Path, users: list) -> None:
    """Write a users.json at *db_path* with the given user records."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(json.dumps({"users": users, "version": 1}), encoding="utf-8")


# ===========================================================================
# TestConsumeCredit
# ===========================================================================


class TestConsumeCredit:
    """Test atomic credit consumption in license_api.consume_credit."""

    def test_consume_credit_success(self, tmp_db: Path) -> None:
        """User with 5 credits: consume 1, verify 4 remaining."""
        _seed_users(tmp_db, [
            {"id": "u1", "email": "test@test.com", "name": "Test",
             "created_at": "2025-01-01T00:00:00+00:00",
             "last_login": "2025-01-01T00:00:00+00:00",
             "auth_method": "email", "password_hash": None,
             "google_id": None, "license_key": None,
             "stripe_customer_id": None, "stripe_subscription_id": None,
             "scan_credits": 5, "credits_used": 0}
        ])

        mgr = UserManager()

        with patch("webapp.license_api.append_audit_log"):
            from webapp.license_api import consume_credit
            result = consume_credit("u1", "audit-123", "127.0.0.1")

        assert result is True
        assert mgr.get_scan_credits("u1") == 4

    def test_consume_credit_zero_balance(self, tmp_db: Path) -> None:
        """User with 0 credits: returns False, no change."""
        _seed_users(tmp_db, [
            {"id": "u1", "email": "test@test.com", "name": "Test",
             "created_at": "2025-01-01T00:00:00+00:00",
             "last_login": "2025-01-01T00:00:00+00:00",
             "auth_method": "email", "password_hash": None,
             "google_id": None, "license_key": None,
             "stripe_customer_id": None, "stripe_subscription_id": None,
             "scan_credits": 0, "credits_used": 0}
        ])

        mgr = UserManager()

        with patch("webapp.license_api.append_audit_log"):
            from webapp.license_api import consume_credit
            result = consume_credit("u1", "audit-123", "127.0.0.1")

        assert result is False
        assert mgr.get_scan_credits("u1") == 0

    def test_consume_credit_unknown_user(self, tmp_db: Path) -> None:
        """Unknown user_id: returns False."""
        _seed_users(tmp_db, [])
        UserManager()  # ensure singleton is initialised

        with patch("webapp.license_api.append_audit_log"):
            from webapp.license_api import consume_credit
            result = consume_credit("nonexistent", "audit-123", "127.0.0.1")

        assert result is False

    def test_consume_credit_concurrent_one_remaining(self, tmp_db: Path) -> None:
        """Two threads with 1 credit: exactly one succeeds (race-condition test)."""
        _seed_users(tmp_db, [
            {"id": "u1", "email": "test@test.com", "name": "Test",
             "created_at": "2025-01-01T00:00:00+00:00",
             "last_login": "2025-01-01T00:00:00+00:00",
             "auth_method": "email", "password_hash": None,
             "google_id": None, "license_key": None,
             "stripe_customer_id": None, "stripe_subscription_id": None,
             "scan_credits": 1, "credits_used": 0}
        ])

        mgr = UserManager()

        with patch("webapp.license_api.append_audit_log"):
            from webapp.license_api import consume_credit
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(consume_credit, "u1", f"audit-{i}", "127.0.0.1")
                    for i in range(2)
                ]
                results = [f.result() for f in as_completed(futures)]

        assert results.count(True) == 1
        assert results.count(False) == 1
        assert mgr.get_scan_credits("u1") == 0

    def test_consume_credit_increments_credits_used(self, tmp_db: Path) -> None:
        """credits_used counter increments on each consume."""
        _seed_users(tmp_db, [
            {"id": "u1", "email": "test@test.com", "name": "Test",
             "created_at": "2025-01-01T00:00:00+00:00",
             "last_login": "2025-01-01T00:00:00+00:00",
             "auth_method": "email", "password_hash": None,
             "google_id": None, "license_key": None,
             "stripe_customer_id": None, "stripe_subscription_id": None,
             "scan_credits": 3, "credits_used": 0}
        ])

        mgr = UserManager()

        with patch("webapp.license_api.append_audit_log"):
            from webapp.license_api import consume_credit
            consume_credit("u1", "a1", "127.0.0.1")
            consume_credit("u1", "a2", "127.0.0.1")

        user = mgr.get_by_id("u1")
        assert user is not None
        assert user["credits_used"] == 2
        assert user["scan_credits"] == 1


# ===========================================================================
# TestScanCreditsManagement
# ===========================================================================


class TestScanCreditsManagement:
    """Test user_manager credit methods (get/set/add)."""

    def test_add_scan_credits(self, manager: UserManager) -> None:
        """Add credits and verify balance."""
        user = manager.create_user(email="test@t.com", name="T", password="pw")
        new_balance = manager.add_scan_credits(user["id"], 5)

        assert new_balance == 5
        assert manager.get_scan_credits(user["id"]) == 5

    def test_add_scan_credits_cumulative(self, manager: UserManager) -> None:
        """Multiple adds accumulate."""
        user = manager.create_user(email="test@t.com", name="T", password="pw")
        manager.add_scan_credits(user["id"], 3)
        new_balance = manager.add_scan_credits(user["id"], 7)

        assert new_balance == 10
        assert manager.get_scan_credits(user["id"]) == 10

    def test_set_scan_credits(self, manager: UserManager) -> None:
        """set_scan_credits overwrites existing balance."""
        user = manager.create_user(email="test@t.com", name="T", password="pw")
        manager.add_scan_credits(user["id"], 10)
        manager.set_scan_credits(user["id"], 3)

        assert manager.get_scan_credits(user["id"]) == 3

    def test_credits_backward_compat(self, tmp_db: Path) -> None:
        """User record without scan_credits field defaults to 0."""
        _seed_users(tmp_db, [
            {"id": "u1", "email": "test@t.com", "name": "T",
             "created_at": "2025-01-01T00:00:00+00:00",
             "last_login": "2025-01-01T00:00:00+00:00",
             "auth_method": "email", "password_hash": None,
             "google_id": None, "license_key": None,
             "stripe_customer_id": None, "stripe_subscription_id": None}
        ])

        mgr = UserManager()
        assert mgr.get_scan_credits("u1") == 0

    def test_get_scan_credits_unknown_user(self, manager: UserManager) -> None:
        """Unknown user returns 0."""
        assert manager.get_scan_credits("nonexistent") == 0

    def test_add_scan_credits_unknown_user(self, manager: UserManager) -> None:
        """add_scan_credits for unknown user returns 0."""
        assert manager.add_scan_credits("nonexistent", 5) == 0
