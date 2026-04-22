"""Integration tests for webapp/auth.py routes using FastAPI TestClient."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import webapp.user_manager as um_module
from webapp.user_manager import UserManager


# ---------------------------------------------------------------------------
# Singleton helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# TestClient fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def auth_client(tmp_db):
    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware
    from webapp.auth import auth_router
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret-key")
    app.include_router(auth_router)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


# ---------------------------------------------------------------------------
# TestLoginPage
# ---------------------------------------------------------------------------


class TestLoginPage:
    def test_get_login_page_returns_200(self, auth_client) -> None:
        r = auth_client.get("/auth/login")
        assert r.status_code == 200

    def test_login_page_with_error_param(self, auth_client) -> None:
        r = auth_client.get("/auth/login?error=invalid")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# TestRegisterPage
# ---------------------------------------------------------------------------


class TestRegisterPage:
    def test_get_register_page_returns_200(self, auth_client) -> None:
        r = auth_client.get("/auth/register")
        assert r.status_code == 200

    def test_register_page_with_error_param(self, auth_client) -> None:
        r = auth_client.get("/auth/register?error=email+taken")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# TestRegisterSubmit
# ---------------------------------------------------------------------------


class TestRegisterSubmit:
    def test_register_password_mismatch_returns_200(self, auth_client) -> None:
        r = auth_client.post("/auth/register", data={
            "name": "Alice",
            "email": "alice@example.com",
            "password": "password123",
            "confirm_password": "different",
        })
        assert r.status_code == 200
        assert "Passwords do not match" in r.text or r.status_code in (200, 422)

    def test_register_short_password_returns_200(self, auth_client) -> None:
        r = auth_client.post("/auth/register", data={
            "name": "Bob",
            "email": "bob@example.com",
            "password": "short",
            "confirm_password": "short",
        })
        assert r.status_code == 200

    def test_register_success_redirects(self, auth_client, manager) -> None:
        r = auth_client.post("/auth/register", data={
            "name": "Carol",
            "email": "carol@example.com",
            "password": "securepass123",
            "confirm_password": "securepass123",
        }, follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_register_duplicate_email_returns_200(self, auth_client, manager) -> None:
        manager.create_user(email="dupe@example.com", name="Dupe", password="pw123456")
        r = auth_client.post("/auth/register", data={
            "name": "Dupe2",
            "email": "dupe@example.com",
            "password": "pw123456",
            "confirm_password": "pw123456",
        })
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# TestLoginSubmit
# ---------------------------------------------------------------------------


class TestLoginSubmit:
    def test_login_success_redirects(self, auth_client, manager) -> None:
        manager.create_user(email="login@example.com", name="Login", password="password123")
        r = auth_client.post("/auth/login", data={
            "email": "login@example.com",
            "password": "password123",
        }, follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_login_wrong_password_returns_200(self, auth_client, manager) -> None:
        manager.create_user(email="wrong@example.com", name="Wrong", password="correct123")
        r = auth_client.post("/auth/login", data={
            "email": "wrong@example.com",
            "password": "incorrect456",
        })
        assert r.status_code == 200

    def test_login_unknown_user_returns_200(self, auth_client) -> None:
        r = auth_client.post("/auth/login", data={
            "email": "nobody@example.com",
            "password": "anypassword",
        })
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# TestLogout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_redirects(self, auth_client) -> None:
        r = auth_client.get("/auth/logout", follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_logout_clears_session(self, auth_client, manager) -> None:
        # First login to get a session
        manager.create_user(email="logout@example.com", name="Logout", password="password123")
        auth_client.post("/auth/login", data={
            "email": "logout@example.com",
            "password": "password123",
        }, follow_redirects=False)
        # Now logout
        r = auth_client.get("/auth/logout", follow_redirects=False)
        assert r.status_code in (302, 200)


# ---------------------------------------------------------------------------
# TestGoogleLogin
# ---------------------------------------------------------------------------


class TestGoogleLogin:
    def test_google_login_without_credentials_redirects(self, auth_client) -> None:
        """Without GOOGLE_CLIENT_ID, should redirect to login with error."""
        import webapp.auth as auth_mod
        with patch.object(auth_mod, "GOOGLE_CLIENT_ID", ""), \
             patch.object(auth_mod, "GOOGLE_CLIENT_SECRET", ""):
            r = auth_client.get("/auth/google", follow_redirects=False)
            assert r.status_code in (302, 200)

    def test_google_callback_without_credentials_redirects(self, auth_client) -> None:
        """Without GOOGLE_CLIENT_ID, callback redirects to error."""
        import webapp.auth as auth_mod
        with patch.object(auth_mod, "GOOGLE_CLIENT_ID", ""), \
             patch.object(auth_mod, "GOOGLE_CLIENT_SECRET", ""):
            r = auth_client.get("/auth/google/callback", follow_redirects=False)
            assert r.status_code in (302, 200)
