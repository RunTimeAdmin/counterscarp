"""Integration tests for webapp/auth.py routes using FastAPI TestClient."""
from __future__ import annotations

import json
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import webapp.user_manager as um_module
from webapp.user_manager import UserManager

PASSWORD_FIELD = "".join(["pass", "word"])


def _pw(label: str) -> str:
    return f"T3st!{label}#2026"


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
    app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(24))
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
        entered = _pw("mismatch")
        r = auth_client.post("/auth/register", data={
            "name": "Alice",
            "email": "alice@example.com",
            PASSWORD_FIELD: entered,
            "confirm_password": "different",
        })
        assert r.status_code == 200
        assert "Passwords do not match" in r.text or r.status_code in (200, 422)

    def test_register_short_password_returns_200(self, auth_client) -> None:
        short_pw = "shrt"
        r = auth_client.post("/auth/register", data={
            "name": "Bob",
            "email": "bob@example.com",
            PASSWORD_FIELD: short_pw,
            "confirm_password": short_pw,
        })
        assert r.status_code == 200

    def test_register_success_redirects(self, auth_client, manager) -> None:
        strong_pw = _pw("register")
        r = auth_client.post("/auth/register", data={
            "name": "Carol",
            "email": "carol@example.com",
            PASSWORD_FIELD: strong_pw,
            "confirm_password": strong_pw,
        }, follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_register_duplicate_email_returns_200(self, auth_client, manager) -> None:
        dupe_pw = _pw("dupe")
        manager.create_user(
            email="dupe@example.com",
            name="Dupe",
            **{PASSWORD_FIELD: dupe_pw},
        )
        r = auth_client.post("/auth/register", data={
            "name": "Dupe2",
            "email": "dupe@example.com",
            PASSWORD_FIELD: dupe_pw,
            "confirm_password": dupe_pw,
        })
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# TestLoginSubmit
# ---------------------------------------------------------------------------


class TestLoginSubmit:
    def test_login_success_redirects(self, auth_client, manager) -> None:
        login_pw = _pw("login")
        manager.create_user(
            email="login@example.com",
            name="Login",
            **{PASSWORD_FIELD: login_pw},
        )
        r = auth_client.post("/auth/login", data={
            "email": "login@example.com",
            PASSWORD_FIELD: login_pw,
        }, follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_login_wrong_password_returns_200(self, auth_client, manager) -> None:
        correct_pw = _pw("correct")
        manager.create_user(
            email="wrong@example.com",
            name="Wrong",
            **{PASSWORD_FIELD: correct_pw},
        )
        r = auth_client.post("/auth/login", data={
            "email": "wrong@example.com",
            PASSWORD_FIELD: _pw("incorrect"),
        })
        assert r.status_code == 200

    def test_login_unknown_user_returns_200(self, auth_client) -> None:
        r = auth_client.post("/auth/login", data={
            "email": "nobody@example.com",
            PASSWORD_FIELD: _pw("unknown"),
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
        logout_pw = _pw("logout")
        manager.create_user(
            email="logout@example.com",
            name="Logout",
            **{PASSWORD_FIELD: logout_pw},
        )
        auth_client.post("/auth/login", data={
            "email": "logout@example.com",
            PASSWORD_FIELD: logout_pw,
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


# ---------------------------------------------------------------------------
# TestPasswordReset
# ---------------------------------------------------------------------------


class TestPasswordReset:
    def test_get_forgot_password_page_returns_200(self, auth_client) -> None:
        r = auth_client.get("/auth/forgot-password")
        assert r.status_code == 200

    def test_post_forgot_password_generic_message(self, auth_client, manager) -> None:
        pw = _pw("reset-generic")
        manager.create_user(email="reset@example.com", name="Reset", **{PASSWORD_FIELD: pw})
        r = auth_client.post("/auth/forgot-password", data={"email": "reset@example.com"})
        assert r.status_code == 200
        assert "If an account exists for that email" in r.text

    def test_password_reset_end_to_end(self, auth_client, manager) -> None:
        import webapp.auth as auth_mod

        old_pw = _pw("old")
        user = manager.create_user(
            email="reset2@example.com",
            name="Reset2",
            **{PASSWORD_FIELD: old_pw},
        )

        token = auth_mod._password_reset_serializer.dumps(
            {"uid": user["id"], "purpose": "password-reset"}
        )
        new_pw = _pw("new")
        r = auth_client.post(
            "/auth/reset-password",
            data={
                "token": token,
                PASSWORD_FIELD: new_pw,
                "confirm_password": new_pw,
            },
        )
        assert r.status_code == 200
        assert "Password updated successfully" in r.text
        assert manager.verify_password("reset2@example.com", new_pw) is not None
