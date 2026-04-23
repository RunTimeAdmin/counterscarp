"""Tests for webapp/stripe_integration.py — mock-based, no real Stripe calls."""

import json
import sys
import os
import types
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import pytest

# ---------------------------------------------------------------------------
# Stub out the `stripe` package before importing stripe_integration so that
# we never make real network calls and don't need stripe installed.
# ---------------------------------------------------------------------------

_stripe_stub = types.ModuleType("stripe")
_stripe_stub.api_key = ""

# Product / Price stubs
_product_stub = MagicMock()
_price_stub = MagicMock()
_stripe_stub.Product = MagicMock()
_stripe_stub.Price = MagicMock()

# Checkout stub
_checkout_stub = types.ModuleType("stripe.checkout")
_session_stub = MagicMock()
_checkout_stub.Session = _session_stub
_stripe_stub.checkout = _checkout_stub

# Webhook stub
_stripe_stub.Webhook = MagicMock()
_stripe_stub.error = types.SimpleNamespace(
    SignatureVerificationError=Exception
)

sys.modules.setdefault("stripe", _stripe_stub)
sys.modules.setdefault("stripe.checkout", _checkout_stub)

# Ensure project root is on the path so ``license_manager`` can be imported
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Now import the module under test
# ---------------------------------------------------------------------------
import importlib
import webapp.stripe_integration as _si_mod

# Reload to pick up the stub (in case stripe was already cached as real)
importlib.reload(_si_mod)

from webapp.stripe_integration import (
    PRODUCTS,
    find_license_by_subscription,
    update_license_in_db,
    handle_checkout_completed,
    get_session_license_key,
    _load_session_map,
    _save_session_map,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_licenses_db(licenses: list) -> dict:
    return {"licenses": licenses, "version": 1}


def _write_db(path: Path, licenses: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_make_licenses_db(licenses), indent=2), encoding="utf-8")


# ===========================================================================
# TestProductConfiguration
# ===========================================================================

class TestProductConfiguration:
    """Tests for the PRODUCTS dict at module level."""

    _REQUIRED_FIELDS = {"name", "description", "price_cents", "interval", "tier", "max_activations"}

    def test_all_products_have_required_fields(self):
        for key, info in PRODUCTS.items():
            missing = self._REQUIRED_FIELDS - set(info.keys())
            assert not missing, f"Product '{key}' missing fields: {missing}"

    def test_product_count(self):
        assert len(PRODUCTS) == 6

    def test_developer_tier_products(self):
        dev_products = {k: v for k, v in PRODUCTS.items() if v["tier"] == "developer"}
        assert len(dev_products) == 2
        keys = set(dev_products.keys())
        assert keys == {"dev_monthly", "dev_annual"}

    def test_pro_tier_products(self):
        pro_products = {k: v for k, v in PRODUCTS.items() if v["tier"] == "pro"}
        assert len(pro_products) == 2
        assert set(pro_products.keys()) == {"pro_monthly", "pro_annual"}

    def test_team_tier_products(self):
        team_products = {k: v for k, v in PRODUCTS.items() if v["tier"] == "team"}
        assert len(team_products) == 2

    def test_intervals_are_valid(self):
        valid_intervals = {"month", "year"}
        for key, info in PRODUCTS.items():
            assert info["interval"] in valid_intervals, f"{key} has invalid interval"

    def test_dev_monthly_price(self):
        assert PRODUCTS["dev_monthly"]["price_cents"] == 4900

    def test_pro_monthly_price(self):
        assert PRODUCTS["pro_monthly"]["price_cents"] == 19900

    def test_team_monthly_price(self):
        assert PRODUCTS["team_monthly"]["price_cents"] == 39900

    def test_dev_max_activations(self):
        assert PRODUCTS["dev_monthly"]["max_activations"] == 1
        assert PRODUCTS["dev_annual"]["max_activations"] == 1

    def test_pro_max_activations(self):
        assert PRODUCTS["pro_monthly"]["max_activations"] == 3
        assert PRODUCTS["pro_annual"]["max_activations"] == 3

    def test_team_max_activations(self):
        assert PRODUCTS["team_monthly"]["max_activations"] == 5
        assert PRODUCTS["team_annual"]["max_activations"] == 5

    def test_annual_prices_greater_than_monthly(self):
        for tier in ("dev", "pro", "team"):
            monthly = PRODUCTS[f"{tier}_monthly"]["price_cents"]
            annual = PRODUCTS[f"{tier}_annual"]["price_cents"]
            assert annual > monthly, f"{tier} annual should cost more than monthly in absolute terms"


# ===========================================================================
# TestFindLicenseBySubscription
# ===========================================================================

class TestFindLicenseBySubscription:
    """Tests for find_license_by_subscription()."""

    def test_finds_matching_license(self):
        licenses = [
            {"key": "SE-PRO-abc123", "stripe_subscription_id": "sub_test1", "tier": "pro"},
            {"key": "SE-DEV-xyz789", "stripe_subscription_id": "sub_test2", "tier": "developer"},
        ]
        db_data = json.dumps(_make_licenses_db(licenses))
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = find_license_by_subscription("sub_test1")

        assert result is not None
        assert result["key"] == "SE-PRO-abc123"

    def test_finds_second_license(self, tmp_path):
        licenses = [
            {"key": "SE-PRO-abc123", "stripe_subscription_id": "sub_A"},
            {"key": "SE-DEV-xyz789", "stripe_subscription_id": "sub_B"},
        ]
        db_data = json.dumps(_make_licenses_db(licenses))
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = find_license_by_subscription("sub_B")
        assert result is not None
        assert result["key"] == "SE-DEV-xyz789"

    def test_returns_none_when_not_found(self):
        licenses = [
            {"key": "SE-PRO-abc123", "stripe_subscription_id": "sub_test1"},
        ]
        db_data = json.dumps(_make_licenses_db(licenses))
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = find_license_by_subscription("sub_nonexistent")
        assert result is None

    def test_returns_none_when_db_missing(self):
        with patch("pathlib.Path.exists", return_value=False):
            result = find_license_by_subscription("sub_anything")
        assert result is None

    def test_returns_none_for_empty_license_list(self):
        db_data = json.dumps({"licenses": [], "version": 1})
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = find_license_by_subscription("sub_x")
        assert result is None

    def test_returns_none_when_no_subscription_id_in_entries(self):
        licenses = [{"key": "SE-PRO-nofield", "tier": "pro"}]
        db_data = json.dumps(_make_licenses_db(licenses))
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = find_license_by_subscription("sub_anything")
        assert result is None


# ===========================================================================
# TestUpdateLicenseInDb
# ===========================================================================

class TestUpdateLicenseInDb:
    """Tests for update_license_in_db()."""

    def test_updates_existing_license(self):
        licenses = [
            {"key": "SE-PRO-key1", "tier": "pro", "revoked": False},
            {"key": "SE-DEV-key2", "tier": "developer"},
        ]
        db_data = _make_licenses_db(licenses)
        db_json = json.dumps(db_data)
        written = {}

        def fake_open(path, mode="r", **kwargs):
            if "w" in mode:
                import io
                buf = io.StringIO()
                buf.close = lambda: written.update({"data": buf.getvalue()}) or None
                return buf
            return mock_open(read_data=db_json)()

        m = mock_open(read_data=db_json)

        with patch("builtins.open", m):
            with patch("pathlib.Path.exists", return_value=True):
                result = update_license_in_db("SE-PRO-key1", {"revoked": True, "revoke_reason": "cancelled"})

        assert result is True
        # Verify write was called with updated data
        handle = m()
        handle.write.assert_called()

    def test_returns_false_when_key_not_found(self):
        licenses = [{"key": "SE-PRO-key1", "tier": "pro"}]
        db_data = json.dumps(_make_licenses_db(licenses))
        with patch("builtins.open", mock_open(read_data=db_data)):
            with patch("pathlib.Path.exists", return_value=True):
                result = update_license_in_db("SE-PRO-doesnotexist", {"revoked": True})
        assert result is False

    def test_returns_false_when_db_missing(self):
        with patch("pathlib.Path.exists", return_value=False):
            result = update_license_in_db("SE-PRO-key1", {"tier": "team"})
        assert result is False

    def test_updates_multiple_fields(self):
        licenses = [{"key": "SE-TEAM-key1", "tier": "pro", "max_activations": 3}]
        db_json = json.dumps(_make_licenses_db(licenses))
        m = mock_open(read_data=db_json)
        with patch("builtins.open", m):
            with patch("pathlib.Path.exists", return_value=True):
                result = update_license_in_db(
                    "SE-TEAM-key1",
                    {"tier": "team", "max_activations": 10},
                )
        assert result is True


# ===========================================================================
# TestHandleCheckoutCompleted
# ===========================================================================

class TestHandleCheckoutCompleted:
    """Tests for handle_checkout_completed()."""

    def _make_session(self, product_key="pro_monthly", subscription="sub_abc", customer="cus_xyz", email="user@example.com"):
        return {
            "id": "cs_test_session123",
            "customer_details": {"email": email},
            "customer_email": "",
            "metadata": {"product_key": product_key},
            "subscription": subscription,
            "customer": customer,
        }

    def test_returns_license_entry_dict(self):
        session = self._make_session()
        fake_entry = {
            "key": "SE-PRO-fake123",
            "tier": "pro",
            "customer_email": "user@example.com",
            "expires_at": "2027-01-01",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        assert result["key"] == "SE-PRO-fake123"

    def test_attaches_subscription_id(self):
        session = self._make_session(subscription="sub_test999")
        fake_entry = {
            "key": "SE-PRO-fake456",
            "tier": "pro",
            "customer_email": "buyer@example.com",
            "expires_at": "2027-01-01",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        assert result["stripe_subscription_id"] == "sub_test999"

    def test_attaches_customer_id(self):
        session = self._make_session(customer="cus_customer1")
        fake_entry = {
            "key": "SE-PRO-fake789",
            "tier": "pro",
            "customer_email": "buyer@example.com",
            "expires_at": "2027-01-01",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        assert result["stripe_customer_id"] == "cus_customer1"

    def test_stores_billing_interval_monthly(self):
        session = self._make_session(product_key="pro_monthly")
        fake_entry = {
            "key": "SE-PRO-monthly1",
            "tier": "pro",
            "customer_email": "",
            "expires_at": "2026-05-21",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        assert result["billing_interval"] == "month"

    def test_stores_billing_interval_annual(self):
        session = self._make_session(product_key="pro_annual")
        fake_entry = {
            "key": "SE-PRO-annual1",
            "tier": "pro",
            "customer_email": "",
            "expires_at": "2027-04-21",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        assert result["billing_interval"] == "year"

    def test_falls_back_to_pro_monthly_for_unknown_product(self):
        session = self._make_session(product_key="unknown_key")
        fake_entry = {
            "key": "SE-PRO-fallback1",
            "tier": "pro",
            "customer_email": "",
            "expires_at": "2026-05-21",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry) as mock_gen:
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        result = handle_checkout_completed(session)
        # Should have used pro_monthly fallback (tier=pro, max_activations=3)
        call_kwargs = mock_gen.call_args
        assert call_kwargs[1]["tier"] == "pro"

    def test_uses_customer_details_email(self):
        session = self._make_session(email="specific@test.com")
        fake_entry = {
            "key": "SE-PRO-emailtest",
            "tier": "pro",
            "customer_email": "specific@test.com",
            "expires_at": "2026-05-21",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry) as mock_gen:
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        handle_checkout_completed(session)
        mock_gen.assert_called_once()
        assert mock_gen.call_args[1]["email"] == "specific@test.com"

    def test_saves_session_map_entry(self):
        session = self._make_session()
        session_map_saved = {}
        fake_entry = {
            "key": "SE-PRO-sessmap",
            "tier": "pro",
            "customer_email": "user@example.com",
            "expires_at": "2026-05-21",
            "max_activations": 3,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }

        def capture_save(data):
            session_map_saved.update(data)

        with patch("license_manager.generate_license_key", return_value=fake_entry):
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map", side_effect=capture_save):
                        handle_checkout_completed(session)

        assert "cs_test_session123" in session_map_saved
        entry = session_map_saved["cs_test_session123"]
        assert entry["key"] == "SE-PRO-sessmap"

    def test_dev_product_tier_passed_to_generate(self):
        session = self._make_session(product_key="dev_monthly")
        fake_entry = {
            "key": "SE-DEV-devtest",
            "tier": "developer",
            "customer_email": "",
            "expires_at": "2026-05-21",
            "max_activations": 1,
            "activated_machines": [],
            "revoked": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("license_manager.generate_license_key", return_value=fake_entry) as mock_gen:
            with patch("license_manager._save_license_to_db"):
                with patch("webapp.stripe_integration._load_session_map", return_value={}):
                    with patch("webapp.stripe_integration._save_session_map"):
                        handle_checkout_completed(session)
        assert mock_gen.call_args[1]["tier"] == "developer"
        assert mock_gen.call_args[1]["max_activations"] == 1


# ===========================================================================
# TestGetSessionLicenseKey
# ===========================================================================

class TestGetSessionLicenseKey:
    """Tests for get_session_license_key()."""

    def test_returns_license_info_when_found(self):
        session_map = {
            "cs_test_abc": {"key": "SE-PRO-maptest", "tier": "pro", "customer_email": "a@b.com", "expires_at": "2027-01-01"},
        }
        with patch("webapp.stripe_integration._load_session_map", return_value=session_map):
            result = get_session_license_key("cs_test_abc")
        assert result is not None
        assert result["key"] == "SE-PRO-maptest"

    def test_returns_none_when_not_found(self):
        session_map = {}
        with patch("webapp.stripe_integration._load_session_map", return_value=session_map):
            result = get_session_license_key("cs_nonexistent")
        assert result is None


# ===========================================================================
# TestSessionMap (internal helpers)
# ===========================================================================

class TestSessionMap:
    """Tests for _load_session_map and _save_session_map."""

    def test_load_session_map_missing_file(self, tmp_path):
        # Redirect _SESSION_MAP_PATH to a non-existent file
        missing = tmp_path / "nonexistent.json"
        with patch.object(_si_mod, "_SESSION_MAP_PATH", missing):
            result = _load_session_map()
        assert result == {}

    def test_load_session_map_returns_data(self, tmp_path):
        data = {"cs_abc": {"key": "SE-PRO-loaded"}}
        map_file = tmp_path / "session_license_map.json"
        map_file.write_text(json.dumps(data), encoding="utf-8")
        with patch.object(_si_mod, "_SESSION_MAP_PATH", map_file):
            result = _load_session_map()
        assert result == data

    def test_load_session_map_corrupt_json(self, tmp_path):
        map_file = tmp_path / "session_license_map.json"
        map_file.write_text("not valid json{{", encoding="utf-8")
        with patch.object(_si_mod, "_SESSION_MAP_PATH", map_file):
            result = _load_session_map()
        assert result == {}

    def test_save_and_reload_session_map(self, tmp_path):
        map_file = tmp_path / "data" / "session_license_map.json"
        data = {"cs_xyz": {"key": "SE-PRO-roundtrip", "tier": "pro"}}
        with patch.object(_si_mod, "_SESSION_MAP_PATH", map_file):
            _save_session_map(data)
            result = _load_session_map()
        assert result == data
