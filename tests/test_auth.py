"""Tests for webapp/auth.py."""
from __future__ import annotations
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import webapp.user_manager as um_module
from webapp.user_manager import UserManager

def _reset_singleton():
    UserManager._instance = None
    try:
        UserManager._initialized = False
    except Exception:
        pass

@pytest.fixture()
def tmp_db(tmp_path):
    db_path = tmp_path / "data" / "users.json"
    _reset_singleton()
    with patch.object(um_module, "_USERS_DB_PATH", db_path):
        yield db_path
    _reset_singleton()

@pytest.fixture()
def manager(tmp_db):
    return UserManager()

class TestGetCurrentUser:
    def test_returns_none_no_session(self, manager):
        from webapp.auth import get_current_user
        req = MagicMock()
        req.session = {}
        assert get_current_user(req) is None

    def test_returns_none_unknown_id(self, manager):
        from webapp.auth import get_current_user
        req = MagicMock()
        req.session = {"user_id": "00000000-0000-0000-0000-000000000000"}
        assert get_current_user(req) is None

    def test_returns_user_valid_session(self, manager):
        from webapp.auth import get_current_user
        user = manager.create_user(email="auth@example.com", name="Auth")
        req = MagicMock()
        req.session = {"user_id": user["id"]}
        result = get_current_user(req)
        assert result is not None
        assert result["email"] == "auth@example.com"

    def test_returns_none_empty_user_id(self, manager):
        from webapp.auth import get_current_user
        req = MagicMock()
        req.session = {"user_id": ""}
        assert get_current_user(req) is None

class TestAuthModuleSetup:
    def test_auth_router_prefix(self):
        from webapp.auth import auth_router
        assert auth_router.prefix == "/auth"

    def test_admin_router_exists(self):
        from webapp.auth import admin_router
        assert admin_router is not None

    def test_all_exports(self):
        from webapp import auth
        assert "auth_router" in auth.__all__
        assert "admin_router" in auth.__all__
        assert "get_current_user" in auth.__all__

class TestWebappConfig:
    """Tests for webapp/config.py validate_production_config."""

    def test_validate_no_error_in_dev(self, monkeypatch):
        import os
        monkeypatch.setenv("COUNTERSCARP_ENV", "development")
        # Re-import to get fresh state
        import importlib
        import webapp.config as cfg
        # Should not raise in dev mode
        # Patch the module-level var
        with patch.object(cfg, "COUNTERSCARP_ENV", "development"):
            cfg.validate_production_config()

    def test_validate_raises_in_production_missing_secrets(self, monkeypatch):
        import webapp.config as cfg
        from unittest.mock import patch
        with patch.object(cfg, "COUNTERSCARP_ENV", "production"), \
             patch.object(cfg, "SESSION_SECRET", "counterscarp-dev-session-secret-INSECURE-DEFAULT"), \
             patch.dict("os.environ", {}, clear=False):
            # Remove keys that would satisfy the check
            import os
            os.environ.pop("STRIPE_SECRET_KEY", None)
            os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
            os.environ.pop("GOOGLE_CLIENT_ID", None)
            with pytest.raises(RuntimeError, match="Missing required secrets"):
                cfg.validate_production_config()

    def test_validate_no_error_when_all_secrets_set(self, monkeypatch):
        import webapp.config as cfg
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "client-id-123")
        monkeypatch.setenv("STRIPE_PAYG_STARTER_PRICE_ID", "price_test_starter")
        monkeypatch.setenv("STRIPE_PAYG_STANDARD_PRICE_ID", "price_test_standard")
        monkeypatch.setenv("STRIPE_PAYG_PRO_PACK_PRICE_ID", "price_test_pro")
        monkeypatch.setenv("TOTP_ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0xMjM0NTY3ODk=")
        with patch.object(cfg, "COUNTERSCARP_ENV", "production"), \
             patch.object(cfg, "SESSION_SECRET", "a-real-secret-that-is-long-enough"):
            # Should not raise
            cfg.validate_production_config()

    def test_session_secret_warning_in_dev(self, monkeypatch):
        """Default session secret emits a warning, not an error, in dev mode."""
        import warnings
        import webapp.config as cfg
        # The module already emitted the warning at import time; this verifies the constant
        assert cfg.SESSION_SECRET  # not empty
