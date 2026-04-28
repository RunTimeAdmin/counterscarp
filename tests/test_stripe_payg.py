"""Tests for Stripe PAYG integration — checkout and webhook handling."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

import webapp.user_manager as um_module
from webapp.user_manager import UserManager

# ---------------------------------------------------------------------------
# Stripe stub (same pattern as test_stripe_integration.py)
# ---------------------------------------------------------------------------

_stripe_stub = types.ModuleType("stripe")
_stripe_stub.api_key = ""
_stripe_stub.Product = MagicMock()
_stripe_stub.Price = MagicMock()

_checkout_stub = types.ModuleType("stripe.checkout")
_session_stub = MagicMock()
_checkout_stub.Session = _session_stub
_stripe_stub.checkout = _checkout_stub

_stripe_stub.Webhook = MagicMock()
_stripe_stub.error = types.SimpleNamespace(SignatureVerificationError=Exception)

sys.modules.setdefault("stripe", _stripe_stub)
sys.modules.setdefault("stripe.checkout", _checkout_stub)

# ---------------------------------------------------------------------------
# Import module under test (after stub)
# ---------------------------------------------------------------------------

import importlib
import webapp.stripe_integration as _si_mod

importlib.reload(_si_mod)

from webapp.stripe_integration import (
    PAYG_PACKS,
    create_payg_checkout,
    link_payg_credits_to_user,
    handle_checkout_completed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_singleton() -> None:
    UserManager._instance = None
    try:
        UserManager._initialized = False
    except Exception:
        pass


def _seed_users(db_path: Path, users: list) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(json.dumps({"users": users, "version": 1}), encoding="utf-8")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Generator[Path, None, None]:
    db_path = tmp_path / "data" / "users.json"
    _reset_singleton()
    with patch.object(um_module, "_USERS_DB_PATH", db_path):
        yield db_path
    _reset_singleton()


@pytest.fixture()
def manager(tmp_db: Path) -> UserManager:
    return UserManager()


# ===========================================================================
# TestPaygCheckout
# ===========================================================================


class TestPaygCheckout:
    """Test PAYG checkout session creation."""

    def test_payg_checkout_creates_payment_session(self) -> None:
        """Verify create_payg_checkout uses mode='payment' and correct metadata."""
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/test"

        with patch("webapp.stripe_integration.stripe") as mock_stripe, \
             patch.dict("os.environ", {"STRIPE_PAYG_STANDARD_PRICE_ID": "price_test123"}):
            mock_stripe.checkout.Session.create.return_value = mock_session
            session = create_payg_checkout(
                pack_key="payg_standard",
                user_email="test@test.com",
                user_id="u1",
                success_url="https://example.com/success",
                cancel_url="https://example.com/cancel",
            )

            call_kwargs = mock_stripe.checkout.Session.create.call_args[1]

        assert call_kwargs["mode"] == "payment"
        assert call_kwargs["metadata"]["purchase_type"] == "payg"
        assert call_kwargs["metadata"]["pack_key"] == "payg_standard"
        assert call_kwargs["metadata"]["user_id"] == "u1"
        assert call_kwargs["metadata"]["credits"] == "5"

    def test_payg_checkout_invalid_pack(self) -> None:
        """Unknown pack_key raises ValueError."""
        with pytest.raises(ValueError, match="Unknown PAYG pack"):
            create_payg_checkout(
                pack_key="nonexistent_pack",
                user_email="test@test.com",
                user_id="u1",
                success_url="https://example.com/success",
                cancel_url="https://example.com/cancel",
            )

    def test_payg_checkout_missing_price_id(self) -> None:
        """Missing Stripe Price ID env var raises ValueError."""
        with patch.dict("os.environ", {}, clear=False):
            # Ensure the env var is NOT set
            import os
            os.environ.pop("STRIPE_PAYG_STARTER_PRICE_ID", None)
            with pytest.raises(ValueError, match="Stripe Price ID not configured"):
                create_payg_checkout(
                    pack_key="payg_starter",
                    user_email="test@test.com",
                    user_id="u1",
                    success_url="https://example.com/success",
                    cancel_url="https://example.com/cancel",
                )


# ===========================================================================
# TestPaygWebhook
# ===========================================================================


class TestPaygWebhook:
    """Test webhook PAYG branch — link_payg_credits_to_user and handle_checkout_completed."""

    def test_link_payg_credits_standard(self, tmp_db: Path) -> None:
        """link_payg_credits_to_user grants standard pack credits."""
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

        with patch("webapp.stripe_integration.append_audit_log"):
            new_balance = link_payg_credits_to_user("u1", "payg_standard")

        assert new_balance == 5
        assert mgr.get_scan_credits("u1") == 5

    def test_link_payg_credits_pro_pack(self, tmp_db: Path) -> None:
        """link_payg_credits_to_user grants pro pack credits."""
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

        with patch("webapp.stripe_integration.append_audit_log"):
            new_balance = link_payg_credits_to_user("u1", "payg_pro_pack")

        assert new_balance == 15
        assert mgr.get_scan_credits("u1") == 15

    def test_link_payg_credits_unknown_pack(self) -> None:
        """Unknown pack_key returns 0 credits."""
        with patch("webapp.stripe_integration.append_audit_log"):
            result = link_payg_credits_to_user("u1", "nonexistent_pack")

        assert result == 0

    def test_link_payg_credits_cumulative(self, tmp_db: Path) -> None:
        """Purchasing two packs accumulates credits."""
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

        with patch("webapp.stripe_integration.append_audit_log"):
            link_payg_credits_to_user("u1", "payg_starter")
            balance = link_payg_credits_to_user("u1", "payg_standard")

        assert balance == 6  # 1 + 5
        assert mgr.get_scan_credits("u1") == 6

    def test_handle_checkout_completed_payg_branch(self, tmp_db: Path) -> None:
        """handle_checkout_completed routes PAYG metadata to credit granting."""
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

        session_event = {
            "id": "cs_test_payg_123",
            "metadata": {
                "purchase_type": "payg",
                "pack_key": "payg_standard",
                "user_id": "u1",
                "credits": "5",
            },
        }

        with patch("webapp.stripe_integration.append_audit_log"):
            result = handle_checkout_completed(session_event)

        # PAYG branch returns empty dict (no license generated)
        assert result == {}
        assert mgr.get_scan_credits("u1") == 5


# ===========================================================================
# TestPaygPacksCatalogue
# ===========================================================================


class TestPaygPacksCatalogue:
    """Verify PAYG_PACKS contains expected packs with correct values."""

    def test_starter_pack(self) -> None:
        assert "payg_starter" in PAYG_PACKS
        assert PAYG_PACKS["payg_starter"]["credits"] == 1
        assert PAYG_PACKS["payg_starter"]["price_cents"] == 999

    def test_standard_pack(self) -> None:
        assert "payg_standard" in PAYG_PACKS
        assert PAYG_PACKS["payg_standard"]["credits"] == 5
        assert PAYG_PACKS["payg_standard"]["price_cents"] == 2999

    def test_pro_pack(self) -> None:
        assert "payg_pro_pack" in PAYG_PACKS
        assert PAYG_PACKS["payg_pro_pack"]["credits"] == 15
        assert PAYG_PACKS["payg_pro_pack"]["price_cents"] == 6999

    def test_all_packs_have_required_fields(self) -> None:
        for key, pack in PAYG_PACKS.items():
            assert "credits" in pack, f"{key} missing 'credits'"
            assert "price_cents" in pack, f"{key} missing 'price_cents'"
            assert "price_id_env" in pack, f"{key} missing 'price_id_env'"
            assert "name" in pack, f"{key} missing 'name'"
            assert "description" in pack, f"{key} missing 'description'"
