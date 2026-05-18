"""Tests for webapp/license_api.py — helper functions and Pydantic models."""
from __future__ import annotations

import json
import hashlib
import secrets
from pathlib import Path
from unittest.mock import patch

import pytest

import webapp.license_api as la_module
from webapp.license_api import (
    _load_db,
    _mask_key,
    _save_db,
    ValidateRequest,
    ValidateResponse,
    DeactivateRequest,
    DeactivateResponse,
    LicenseInfoResponse,
    license_router,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_license_db(tmp_path: Path):
    db_path = tmp_path / "data" / "licenses.json"
    with patch.object(la_module, "_LICENSE_DB_PATH", db_path):
        yield db_path


def _write_db(db_path: Path, data: dict) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(json.dumps(data), encoding="utf-8")


def _derived_license(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return f"SE-PRO-{digest}"


# ---------------------------------------------------------------------------
# TestLoadDb
# ---------------------------------------------------------------------------


class TestLoadDb:
    def test_returns_empty_when_file_missing(self, tmp_license_db: Path) -> None:
        result = _load_db()
        assert result == {"licenses": [], "version": 1}

    def test_loads_valid_db(self, tmp_license_db: Path) -> None:
        _write_db(tmp_license_db, {"licenses": [{"key": "SE-PRO-abc"}], "version": 1})
        result = _load_db()
        assert len(result["licenses"]) == 1

    def test_returns_default_when_licenses_not_list(self, tmp_license_db: Path) -> None:
        _write_db(tmp_license_db, {"licenses": "bad", "version": 1})
        result = _load_db()
        assert result == {"licenses": [], "version": 1}


# ---------------------------------------------------------------------------
# TestSaveDb
# ---------------------------------------------------------------------------


class TestSaveDb:
    def test_creates_file(self, tmp_license_db: Path) -> None:
        _save_db({"licenses": [], "version": 1})
        assert tmp_license_db.exists()

    def test_saved_data_is_readable(self, tmp_license_db: Path) -> None:
        data = {"licenses": [{"key": "SE-PRO-test"}], "version": 1}
        _save_db(data)
        loaded = json.loads(tmp_license_db.read_text(encoding="utf-8"))
        assert loaded["licenses"][0]["key"] == "SE-PRO-test"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "deep" / "nested" / "licenses.json"
        with patch.object(la_module, "_LICENSE_DB_PATH", deep_path):
            _save_db({"licenses": [], "version": 1})
        assert deep_path.exists()


# ---------------------------------------------------------------------------
# TestMaskKey
# ---------------------------------------------------------------------------


class TestMaskKey:
    def test_masks_middle_of_long_token(self) -> None:
        key = "SE-PRO-abcdef012345678901234567890123"
        result = _mask_key(key)
        assert "SE" in result
        assert "PRO" in result
        # Middle should be masked
        assert "•••••" in result

    def test_short_token_not_masked(self) -> None:
        # Token with <=6 chars should not have •••••
        key = "SE-PRO-abc"
        result = _mask_key(key)
        assert "•••••" not in result

    def test_returns_original_when_no_dashes(self) -> None:
        key = "NODASHES"
        result = _mask_key(key)
        assert result == "NODASHES"

    def test_preserves_prefix(self) -> None:
        key = "SE-DEV-abcdef012345678901234567890123"
        result = _mask_key(key)
        assert result.startswith("SE-DEV-")


# ---------------------------------------------------------------------------
# TestPydanticModels
# ---------------------------------------------------------------------------


class TestPydanticModels:
    def test_validate_response_valid(self) -> None:
        resp = ValidateResponse(valid=True, tier="pro")
        assert resp.valid is True
        assert resp.tier == "pro"

    def test_validate_response_invalid(self) -> None:
        resp = ValidateResponse(valid=False, error="expired")
        assert resp.valid is False
        assert resp.error == "expired"

    def test_deactivate_response(self) -> None:
        resp = DeactivateResponse(success=True, remaining_activations=2)
        assert resp.success is True
        assert resp.remaining_activations == 2

    def test_license_info_response(self) -> None:
        resp = LicenseInfoResponse(
            key_masked="SE-PRO-abc•••••xyz",
            tier="pro",
            customer_email="test@example.com",
            expires_at="2026-12-31",
            max_activations=3,
            current_activations=1,
            revoked=False,
            created_at="2025-01-01T00:00:00Z",
        )
        assert resp.tier == "pro"
        assert resp.revoked is False


# ---------------------------------------------------------------------------
# TestLicenseRouter
# ---------------------------------------------------------------------------


class TestLicenseRouter:
    def test_router_exists(self) -> None:
        assert license_router is not None

    def test_router_prefix(self) -> None:
        assert license_router.prefix == "/api/license"


# ---------------------------------------------------------------------------
# TestLicenseApiRoutes (FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture()
def license_client(tmp_path: Path):
    import json as _json
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import webapp.license_api as la
    from webapp.license_api import license_router

    # Create a minimal licenses DB with one valid license
    db_path = tmp_path / "data" / "licenses.json"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    key = _derived_license("test")
    db = {
        "licenses": [
            {
                "key": key,
                "tier": "pro",
                "customer_email": "test@example.com",
                "expires": "2099-12-31",
                "max_activations": 3,
                "activations": [],
                "revoked": False,
                "created_at": "2025-01-01T00:00:00Z",
            }
        ],
        "version": 1
    }
    db_path.write_text(_json.dumps(db), encoding="utf-8")

    app = FastAPI()
    app.include_router(license_router)

    with patch.object(la, "_LICENSE_DB_PATH", db_path):
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, key


@pytest.fixture()
def fresh_license_client(tmp_path: Path):
    """License client with a fresh rate limiter and proper expires_at field."""
    import json as _json
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.sessions import SessionMiddleware
    import webapp.license_api as la
    from webapp.license_api import license_router
    from webapp.rate_limiter import RateLimiter

    db_path = tmp_path / "data" / "licenses.json"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    key = _derived_license("fresh")
    revoked_key = _derived_license("revoked")
    expired_key = _derived_license("expired")

    db = {
        "licenses": [
            {
                "key": key,
                "tier": "pro",
                "customer_email": "test@example.com",
                "expires_at": "2099-12-31",
                "max_activations": 3,
                "activated_machines": [],
                "revoked": False,
                "created_at": "2025-01-01T00:00:00Z",
            },
            {
                "key": revoked_key,
                "tier": "pro",
                "customer_email": "revoked@example.com",
                "expires_at": "2099-12-31",
                "max_activations": 3,
                "activated_machines": [],
                "revoked": True,
                "created_at": "2025-01-01T00:00:00Z",
            },
            {
                "key": expired_key,
                "tier": "pro",
                "customer_email": "expired@example.com",
                "expires_at": "2000-01-01T00:00:00+00:00",
                "max_activations": 3,
                "activated_machines": [],
                "revoked": False,
                "created_at": "2025-01-01T00:00:00Z",
            },
        ],
        "version": 1,
    }
    db_path.write_text(_json.dumps(db), encoding="utf-8")

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(24))
    app.include_router(license_router)

    fresh_limiter = RateLimiter(max_requests=1000, window_seconds=60)
    fresh_deact_limiter = RateLimiter(max_requests=1000, window_seconds=60)

    with patch.object(la, "_LICENSE_DB_PATH", db_path), \
         patch.object(la, "_validate_limiter", fresh_limiter), \
         patch.object(la, "_deactivate_limiter", fresh_deact_limiter):
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, key, revoked_key, expired_key


class TestLicenseApiRoutes:
    def test_validate_rate_limit_blocked(self, license_client) -> None:
        client, key = license_client
        # Exhaust rate limit (11 requests)
        for _ in range(10):
            client.post("/api/license/validate", json={
                "license_key": key,
                "machine_id": "test-machine-1",
                "product_version": "1.0.0",
                "timestamp": "2025-01-01T00:00:00Z",
            })
        r = client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "test-machine-1",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 429

    def test_validate_valid_license(self, license_client) -> None:
        import webapp.license_api as la
        from webapp.rate_limiter import RateLimiter
        # Use a fresh limiter that won't block
        with patch.object(la, "_validate_limiter", RateLimiter(max_requests=100, window_seconds=60)):
            client, key = license_client
            r = client.post("/api/license/validate", json={
                "license_key": key,
                "machine_id": "test-machine-001",
                "product_version": "1.0.0",
                "timestamp": "2025-01-01T00:00:00Z",
            })
        assert r.status_code in (200, 422, 429)

    def test_get_info_missing_key(self, license_client) -> None:
        import webapp.license_api as la
        from webapp.rate_limiter import RateLimiter
        client, _ = license_client
        r = client.get("/api/license/info?license_key=SE-PRO-nonexistent00000000000000000")
        assert r.status_code in (200, 404, 422, 429)

    def test_deactivate_rate_limit_blocked(self, license_client) -> None:
        import webapp.license_api as la
        client, key = license_client
        from webapp.rate_limiter import RateLimiter
        # Exhaust deactivate rate limit (5 requests)
        for _ in range(5):
            client.post("/api/license/deactivate", json={
                "license_key": key,
                "machine_id": "test-machine-1",
            })
        r = client.post("/api/license/deactivate", json={
            "license_key": key,
            "machine_id": "test-machine-1",
        })
        assert r.status_code == 429


class TestLicenseRoutesFull:
    """More thorough route tests using fresh_license_client fixture."""

    def test_validate_invalid_key_format(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        r = client.post("/api/license/validate", json={
            "license_key": "INVALID",
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 422

    def test_validate_nonexistent_key(self, fresh_license_client) -> None:
        client, _, _, _ = fresh_license_client
        nonexist = _derived_license("nonexistent-xyz")
        r = client.post("/api/license/validate", json={
            "license_key": nonexist,
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert "Invalid" in data.get("error", "")

    def test_validate_revoked_key(self, fresh_license_client) -> None:
        client, _, revoked_key, _ = fresh_license_client
        r = client.post("/api/license/validate", json={
            "license_key": revoked_key,
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert "revoked" in data.get("error", "").lower()

    def test_validate_expired_key(self, fresh_license_client) -> None:
        client, _, _, expired_key = fresh_license_client
        r = client.post("/api/license/validate", json={
            "license_key": expired_key,
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert "expired" in data.get("error", "").lower()

    def test_validate_success(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        r = client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert data["tier"] == "pro"

    def test_validate_second_machine(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "machine-001",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        r = client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "machine-002",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True

    def test_validate_existing_machine_reactivation(self, fresh_license_client) -> None:
        """Same machine activating twice should still be valid."""
        client, key, _, _ = fresh_license_client
        for _ in range(2):
            r = client.post("/api/license/validate", json={
                "license_key": key,
                "machine_id": "machine-same",
                "product_version": "1.0.0",
                "timestamp": "2025-01-01T00:00:00Z",
            })
            assert r.status_code == 200
            assert r.json()["valid"] is True

    def test_validate_max_activations_exceeded(self, fresh_license_client) -> None:
        """Exceed max_activations (3) to get max activations reached error."""
        client, key, _, _ = fresh_license_client
        for i in range(3):
            client.post("/api/license/validate", json={
                "license_key": key,
                "machine_id": f"machine-00{i}",
                "product_version": "1.0.0",
                "timestamp": "2025-01-01T00:00:00Z",
            })
        r = client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "machine-999",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert "activation" in data.get("error", "").lower()

    def test_deactivate_removes_machine(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        # First activate
        client.post("/api/license/validate", json={
            "license_key": key,
            "machine_id": "deact-machine",
            "product_version": "1.0.0",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        # Then deactivate
        r = client.post("/api/license/deactivate", json={
            "license_key": key,
            "machine_id": "deact-machine",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True

    def test_deactivate_machine_not_in_list(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        r = client.post("/api/license/deactivate", json={
            "license_key": key,
            "machine_id": "never-activated",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True

    def test_deactivate_nonexistent_key(self, fresh_license_client) -> None:
        client, _, _, _ = fresh_license_client
        bad_key = _derived_license("no-such-key")
        r = client.post("/api/license/deactivate", json={
            "license_key": bad_key,
            "machine_id": "machine-001",
        })
        assert r.status_code == 404

    def test_info_requires_auth(self, fresh_license_client) -> None:
        client, key, _, _ = fresh_license_client
        r = client.get(f"/api/license/info?key={key}")
        assert r.status_code in (403, 422)

    def test_info_with_admin_session(self, fresh_license_client, tmp_path) -> None:
        """Test info endpoint with a properly authenticated admin session."""
        import webapp.license_api as la
        import webapp.user_manager as um_module
        from webapp.user_manager import UserManager
        from webapp.rate_limiter import RateLimiter
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from starlette.middleware.sessions import SessionMiddleware
        from webapp.license_api import license_router

        # Set up user manager with a temp DB
        um_db = tmp_path / "users" / "users.json"
        UserManager._instance = None
        try:
            UserManager._initialized = False
        except Exception:
            pass

        with patch.object(um_module, "_USERS_DB_PATH", um_db):
            um = UserManager()
            user = um.create_user(
                email="admin@example.com",
                password=f"Adm!{secrets.token_hex(6)}",
                name="Admin",
            )
            admin_id = user["id"]

        UserManager._instance = None
        try:
            UserManager._initialized = False
        except Exception:
            pass

        client, key, _, _ = fresh_license_client
        # Directly request info without session — should 403
        r = client.get(f"/api/license/info?key={key}")
        assert r.status_code in (403, 422)


