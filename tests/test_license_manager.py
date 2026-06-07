"""Tests for the license management system."""
import os

import pytest

from license_manager import (
    LicenseManager,
    LicenseError,
    get_machine_fingerprint,
    require_pro,
    AI_COPILOT,
    ATTACK_GRAPH,
    EXPLOIT_GEN,
    TIME_TRAVEL,
    FINGERPRINT,
    SOLANA,
    BRANDED_REPORTS,
    WEB_APP,
    ALL_PRO_FEATURES,
    COMMUNITY,
    PAYG,
    DEVELOPER,
    PRO,
    TEAM,
    ENTERPRISE,
    TIER_HIERARCHY,
    FEATURE_TIERS,
    TIER_PREFIXES,
    TIER_DEFAULT_ACTIVATIONS,
)


class TestMachineFingerprint:
    """Tests for machine fingerprint generation."""

    def test_fingerprint_is_string(self):
        fp = get_machine_fingerprint()
        assert isinstance(fp, str)

    def test_fingerprint_is_hex(self):
        fp = get_machine_fingerprint()
        assert all(c in '0123456789abcdef' for c in fp)

    def test_fingerprint_is_deterministic(self):
        fp1 = get_machine_fingerprint()
        fp2 = get_machine_fingerprint()
        assert fp1 == fp2

    def test_fingerprint_is_sha256_length(self):
        fp = get_machine_fingerprint()
        assert len(fp) == 64  # SHA-256 hex length


class TestLicenseConstants:
    """Tests for pro feature constants."""

    def test_all_features_defined(self):
        assert AI_COPILOT == "ai_copilot"
        assert ATTACK_GRAPH == "attack_graph"
        assert EXPLOIT_GEN == "exploit_gen"
        assert TIME_TRAVEL == "time_travel"
        assert FINGERPRINT == "fingerprint"
        assert SOLANA == "solana"
        assert BRANDED_REPORTS == "branded_reports"
        assert WEB_APP == "web_app"

    def test_all_pro_features_list(self):
        assert len(ALL_PRO_FEATURES) == 8
        assert AI_COPILOT in ALL_PRO_FEATURES
        assert BRANDED_REPORTS in ALL_PRO_FEATURES


class TestLicenseManagerSingleton:
    """Tests for singleton behavior."""

    def test_singleton_returns_same_instance(self):
        # Reset singleton for testing
        LicenseManager._instance = None
        mgr1 = LicenseManager()
        mgr2 = LicenseManager()
        assert mgr1 is mgr2

    def teardown_method(self):
        LicenseManager._instance = None


class TestFreeTier:
    """Tests for free tier behavior (no license key)."""

    def setup_method(self):
        LicenseManager._instance = None
        # Ensure no license env var
        os.environ.pop("SCARPSHIELD_PRO_LICENSE", None)
        os.environ.pop("COUNTERSCARP_PRO_LICENSE", None)

    def teardown_method(self):
        LicenseManager._instance = None

    def test_no_key_returns_community_tier(self):
        mgr = LicenseManager()
        assert mgr.get_tier() == COMMUNITY

    def test_pro_feature_blocked_without_key(self):
        mgr = LicenseManager()
        assert mgr.check_pro_feature(AI_COPILOT) is False

    def test_all_pro_features_blocked(self):
        mgr = LicenseManager()
        for feature in ALL_PRO_FEATURES:
            assert mgr.check_pro_feature(feature) is False

    def test_require_pro_raises_error(self):
        mgr = LicenseManager()
        with pytest.raises(LicenseError):
            mgr.require_pro_feature(AI_COPILOT)

    def test_community_tier_shows_community(self):
        mgr = LicenseManager()
        info = mgr.get_license_info()
        assert info.tier == COMMUNITY
        assert info.valid is False or info.features == []


class TestUpgradeMessage:
    """Tests for upgrade message formatting."""

    def test_upgrade_message_contains_feature_name(self):
        msg = LicenseManager.get_upgrade_message(AI_COPILOT)
        assert "AI Audit Copilot" in msg

    def test_upgrade_message_contains_pricing_url(self):
        msg = LicenseManager.get_upgrade_message(ATTACK_GRAPH)
        assert "app.counterscarp.io/pricing" in msg

    def test_upgrade_message_for_all_features(self):
        for feature in ALL_PRO_FEATURES:
            msg = LicenseManager.get_upgrade_message(feature)
            assert isinstance(msg, str)
            assert len(msg) > 50  # Should be a substantial message


class TestRequireProDecorator:
    """Tests for the require_pro decorator."""

    def setup_method(self):
        LicenseManager._instance = None
        os.environ.pop("SCARPSHIELD_PRO_LICENSE", None)
        os.environ.pop("COUNTERSCARP_PRO_LICENSE", None)

    def teardown_method(self):
        LicenseManager._instance = None

    def test_decorated_function_returns_none_without_license(self):
        @require_pro(AI_COPILOT)
        def pro_function():
            return "pro result"

        result = pro_function()
        assert result is None

    def test_decorated_function_preserves_name(self):
        @require_pro(AI_COPILOT)
        def my_pro_function():
            """My docstring."""
            return "result"

        assert my_pro_function.__name__ == "my_pro_function"
        assert my_pro_function.__doc__ == "My docstring."


class TestLicenseError:
    """Tests for the LicenseError exception."""

    def test_error_includes_feature(self):
        err = LicenseError(AI_COPILOT)
        assert err.feature == AI_COPILOT

    def test_error_message(self):
        err = LicenseError(AI_COPILOT)
        assert "ai_copilot" in str(err) or "Pro" in str(err)

    def test_custom_message(self):
        err = LicenseError(AI_COPILOT, "Custom error")
        assert str(err) == "Custom error"


class TestKeyGeneration:
    """Tests for license key generation."""

    def test_generate_key_format(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "pro", "test@example.com", "2027-12-31", 2
        )
        assert entry["key"].startswith("SE-PRO-")
        assert entry["tier"] == "pro"
        assert entry["customer_email"] == "test@example.com"
        assert entry["max_activations"] == 2
        assert entry["revoked"] is False
        assert entry["activated_machines"] == []

    def test_generate_enterprise_key(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "enterprise", "corp@example.com", "2028-01-01", 100
        )
        assert entry["key"].startswith("SE-ENT-")
        assert entry["tier"] == "enterprise"
        assert entry["max_activations"] == 100

    def test_generate_developer_key(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "developer", "dev@example.com", "2027-06-30"
        )
        assert entry["key"].startswith("SE-DEV-")
        assert entry["tier"] == "developer"
        assert entry["max_activations"] == 1  # default for developer

    def test_generate_team_key(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "team", "team@example.com", "2027-06-30"
        )
        assert entry["key"].startswith("SE-TEAM-")
        assert entry["tier"] == "team"
        assert entry["max_activations"] == 5  # default for team

    def test_default_activations_per_tier(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "pro", "pro@example.com", "2027-06-30"
        )
        assert entry["max_activations"] == 3  # default for pro

    def test_explicit_activations_overrides_default(self):
        from license_manager import generate_license_key
        entry = generate_license_key(
            "pro", "pro@example.com", "2027-06-30", 5
        )
        assert entry["max_activations"] == 5


class TestTierHierarchy:
    """Tests for tier hierarchy and feature gating."""

    def test_tier_hierarchy_order(self):
        assert TIER_HIERARCHY == [
            COMMUNITY, PAYG, DEVELOPER, PRO, TEAM, ENTERPRISE
        ]

    def test_feature_tiers_mapping(self):
        assert FEATURE_TIERS[SOLANA] == DEVELOPER
        assert FEATURE_TIERS[BRANDED_REPORTS] == DEVELOPER
        assert FEATURE_TIERS[WEB_APP] == DEVELOPER
        assert FEATURE_TIERS[AI_COPILOT] == PRO
        assert FEATURE_TIERS[ATTACK_GRAPH] == PRO
        assert FEATURE_TIERS[EXPLOIT_GEN] == PRO
        assert FEATURE_TIERS[TIME_TRAVEL] == PRO
        assert FEATURE_TIERS[FINGERPRINT] == PRO

    def test_tier_prefixes(self):
        assert TIER_PREFIXES[DEVELOPER] == "SE-DEV-"
        assert TIER_PREFIXES[PRO] == "SE-PRO-"
        assert TIER_PREFIXES[TEAM] == "SE-TEAM-"
        assert TIER_PREFIXES[ENTERPRISE] == "SE-ENT-"

    def test_default_activations(self):
        assert TIER_DEFAULT_ACTIVATIONS[DEVELOPER] == 1
        assert TIER_DEFAULT_ACTIVATIONS[PRO] == 3
        assert TIER_DEFAULT_ACTIVATIONS[TEAM] == 5
        assert TIER_DEFAULT_ACTIVATIONS[ENTERPRISE] == 100


class TestTierFromKeyPrefix:
    """Tests for _tier_from_key_prefix fallback."""

    def setup_method(self):
        LicenseManager._instance = None
        os.environ.pop("SCARPSHIELD_PRO_LICENSE", None)
        os.environ.pop("COUNTERSCARP_PRO_LICENSE", None)

    def teardown_method(self):
        LicenseManager._instance = None

    def test_dev_prefix_returns_developer(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-DEV-abcdef1234567890"
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == DEVELOPER

    def test_pro_prefix_returns_pro(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-PRO-abcdef1234567890"
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == PRO

    def test_team_prefix_returns_team(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-TEAM-abcdef1234567890"
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == TEAM

    def test_ent_prefix_returns_enterprise(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-ENT-abcdef1234567890"
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == ENTERPRISE

    def test_legacy_enterprise_prefix(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = (
            "SE-ENTERPRISE-abcdef1234567890"
        )
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == ENTERPRISE

    def test_unknown_prefix_returns_community(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-UNKNOWN-abcdef1234567890"
        LicenseManager._instance = None
        mgr = LicenseManager()
        assert mgr._tier_from_key_prefix() == COMMUNITY


class TestPreferredEnvVar:
    """Tests env var alias preference for license key loading."""

    def setup_method(self):
        LicenseManager._instance = None
        os.environ.pop("SCARPSHIELD_PRO_LICENSE", None)
        os.environ.pop("COUNTERSCARP_PRO_LICENSE", None)

    def teardown_method(self):
        LicenseManager._instance = None
        os.environ.pop("SCARPSHIELD_PRO_LICENSE", None)
        os.environ.pop("COUNTERSCARP_PRO_LICENSE", None)

    def test_prefers_scarpshield_env_var_over_legacy(self):
        os.environ["SCARPSHIELD_PRO_LICENSE"] = "SE-PRO-preferred"
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-PRO-legacy"
        mgr = LicenseManager()
        assert mgr._license_key == "SE-PRO-preferred"

    def test_uses_legacy_env_var_when_preferred_missing(self):
        os.environ["COUNTERSCARP_PRO_LICENSE"] = "SE-PRO-legacy"
        mgr = LicenseManager()
        assert mgr._license_key == "SE-PRO-legacy"

    def test_loads_license_key_from_scarpshield_toml(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "scarpshield.toml"
        config_file.write_text(
            "[license]\nkey = \"SE-PRO-from-config\"\n",
            encoding="utf-8",
        )
        mgr = LicenseManager()
        assert mgr._license_key == "SE-PRO-from-config"


class TestUpgradeMessageTiers:
    """Tests for tier-specific upgrade messages."""

    def test_developer_feature_message(self):
        msg = LicenseManager.get_upgrade_message(SOLANA)
        assert "Developer" in msg
        assert "$49/mo" in msg

    def test_pro_feature_message(self):
        msg = LicenseManager.get_upgrade_message(AI_COPILOT)
        assert "Pro" in msg
        assert "$149/mo" in msg
