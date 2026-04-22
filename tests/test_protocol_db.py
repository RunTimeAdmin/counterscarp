"""
Tests for the protocol_db module.
"""

import pytest
import sys
import os
import json
import tempfile

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from protocol_db import (
    ProtocolFingerprint,
    get_default_fingerprints,
    save_fingerprint_db,
    load_fingerprint_db,
    get_fingerprint_by_name,
    get_fingerprints_by_category,
)


# =============================================================================
# ProtocolFingerprint Tests
# =============================================================================

class TestProtocolFingerprint:
    """Test ProtocolFingerprint dataclass."""

    def test_creation(self):
        """Test creating a ProtocolFingerprint."""
        fp = ProtocolFingerprint(
            name="Test Protocol",
            category="DeFi",
            version="1.0",
            function_signatures=["transfer(address,uint256)"],
            event_signatures=["Transfer(address,address,uint256)"],
            storage_patterns=[r"balance"],
            inheritance_markers=["ITest"],
            constants={"MAX": "1000"},
            known_vulnerabilities=[{"id": "TEST-001", "severity": "HIGH"}]
        )
        
        assert fp.name == "Test Protocol"
        assert fp.category == "DeFi"
        assert fp.version == "1.0"

    def test_default_values(self):
        """Test ProtocolFingerprint with default values."""
        fp = ProtocolFingerprint(
            name="Test",
            category="Test",
            version="1.0"
        )
        
        assert fp.function_signatures == []
        assert fp.event_signatures == []
        assert fp.storage_patterns == []
        assert fp.inheritance_markers == []
        assert fp.constants == {}
        assert fp.known_vulnerabilities == []

    def test_to_dict(self):
        """Test converting to dictionary."""
        fp = ProtocolFingerprint(
            name="Test",
            category="DeFi",
            version="1.0",
            function_signatures=["test()"]
        )
        
        data = fp.to_dict()
        
        assert data["name"] == "Test"
        assert data["category"] == "DeFi"
        assert data["function_signatures"] == ["test()"]

    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "name": "Test",
            "category": "DeFi",
            "version": "1.0",
            "function_signatures": ["test()"],
            "event_signatures": [],
            "storage_patterns": [],
            "inheritance_markers": [],
            "constants": {},
            "known_vulnerabilities": []
        }
        
        fp = ProtocolFingerprint.from_dict(data)
        
        assert fp.name == "Test"
        assert fp.category == "DeFi"
        assert fp.function_signatures == ["test()"]


# =============================================================================
# get_default_fingerprints Tests
# =============================================================================

class TestGetDefaultFingerprints:
    """Test get_default_fingerprints function."""

    def test_returns_all_protocols(self):
        """Test that all 18 default protocols are returned."""
        fingerprints = get_default_fingerprints()
        
        assert len(fingerprints) == 27

    def test_protocol_names(self):
        """Test that expected protocols are included."""
        fingerprints = get_default_fingerprints()
        names = [fp.name for fp in fingerprints]
        
        assert "Uniswap V2" in names
        assert "Uniswap V3" in names
        assert "Compound V2" in names
        assert "Aave V2/V3" in names
        assert "OpenZeppelin" in names
        assert "Curve" in names
        assert "MakerDAO" in names

    def test_protocol_categories(self):
        """Test that protocols have correct categories."""
        fingerprints = get_default_fingerprints()
        
        categories = {fp.category for fp in fingerprints}
        
        assert "AMM" in categories
        assert "Lending" in categories
        assert "AccessControl" in categories
        assert "Stableswap" in categories
        assert "CDP" in categories

    def test_required_fields_present(self):
        """Test that each protocol has required fields."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            assert fp.name
            assert fp.category
            assert fp.version
            assert isinstance(fp.function_signatures, list)
            assert isinstance(fp.event_signatures, list)
            assert isinstance(fp.storage_patterns, list)
            assert isinstance(fp.inheritance_markers, list)
            assert isinstance(fp.constants, dict)
            assert isinstance(fp.known_vulnerabilities, list)

    def test_no_empty_function_lists(self):
        """Test that protocols have at least some function signatures."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            assert len(fp.function_signatures) > 0, \
                f"{fp.name} has no function signatures"

    def test_no_empty_event_lists(self):
        """Test that protocols have at least some event signatures."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            assert len(fp.event_signatures) > 0, \
                f"{fp.name} has no event signatures"

    def test_vulnerabilities_have_required_fields(self):
        """Test that vulnerabilities have required fields."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            for vuln in fp.known_vulnerabilities:
                assert "id" in vuln
                assert "title" in vuln
                assert "severity" in vuln
                assert "description" in vuln
                assert "reference_url" in vuln

    def test_uniswap_v2_fingerprint(self):
        """Test Uniswap V2 fingerprint details."""
        fingerprints = get_default_fingerprints()
        uniswap = next(fp for fp in fingerprints if fp.name == "Uniswap V2")
        
        assert uniswap.category == "AMM"
        assert "swap(uint256,uint256,address,bytes)" in \
               uniswap.function_signatures
        assert "IUniswapV2Pair" in uniswap.inheritance_markers
        assert "MINIMUM_LIQUIDITY" in uniswap.constants

    def test_openzeppelin_fingerprint(self):
        """Test OpenZeppelin fingerprint details."""
        fingerprints = get_default_fingerprints()
        oz = next(fp for fp in fingerprints if fp.name == "OpenZeppelin")
        
        assert oz.category == "AccessControl"
        assert "Ownable" in oz.inheritance_markers
        assert "AccessControl" in oz.inheritance_markers
        assert "upgradeTo(address)" in oz.function_signatures

    def test_curve_fingerprint(self):
        """Test Curve fingerprint details."""
        fingerprints = get_default_fingerprints()
        curve = next(fp for fp in fingerprints if fp.name == "Curve")
        
        assert curve.category == "Stableswap"
        assert "exchange(int128,int128,uint256,uint256)" in \
               curve.function_signatures
        assert "A_PRECISION" in curve.constants


# =============================================================================
# save_fingerprint_db Tests
# =============================================================================

class TestSaveFingerprintDb:
    """Test save_fingerprint_db function."""

    def test_save_to_file(self, tmp_path):
        """Test saving fingerprints to file."""
        fingerprints = [
            ProtocolFingerprint(
                name="Test",
                category="Test",
                version="1.0",
                function_signatures=["test()"]
            )
        ]
        
        output_path = str(tmp_path / "fingerprints.json")
        save_fingerprint_db(fingerprints, output_path)
        
        assert os.path.exists(output_path)
        
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["name"] == "Test"

    def test_creates_directories(self, tmp_path):
        """Test that function creates parent directories."""
        fingerprints = []
        output_path = str(tmp_path / "subdir" / "fingerprints.json")
        
        save_fingerprint_db(fingerprints, output_path)
        
        assert os.path.exists(output_path)


# =============================================================================
# load_fingerprint_db Tests
# =============================================================================

class TestLoadFingerprintDb:
    """Test load_fingerprint_db function."""

    def test_load_from_file(self, tmp_path):
        """Test loading fingerprints from file."""
        data = [
            {
                "name": "Test",
                "category": "DeFi",
                "version": "1.0",
                "function_signatures": ["test()"],
                "event_signatures": [],
                "storage_patterns": [],
                "inheritance_markers": [],
                "constants": {},
                "known_vulnerabilities": []
            }
        ]
        
        input_path = str(tmp_path / "fingerprints.json")
        with open(input_path, 'w') as f:
            json.dump(data, f)
        
        fingerprints = load_fingerprint_db(input_path)
        
        assert len(fingerprints) == 1
        assert fingerprints[0].name == "Test"
        assert isinstance(fingerprints[0], ProtocolFingerprint)

    def test_load_invalid_json(self, tmp_path):
        """Test loading invalid JSON."""
        input_path = str(tmp_path / "invalid.json")
        with open(input_path, 'w') as f:
            f.write("not valid json")
        
        with pytest.raises(Exception):
            load_fingerprint_db(input_path)

    def test_load_missing_file(self, tmp_path):
        """Test loading missing file."""
        with pytest.raises(Exception):
            load_fingerprint_db(str(tmp_path / "nonexistent.json"))


# =============================================================================
# get_fingerprint_by_name Tests
# =============================================================================

class TestGetFingerprintByName:
    """Test get_fingerprint_by_name function."""

    def test_find_existing(self):
        """Test finding an existing fingerprint."""
        result = get_fingerprint_by_name("Uniswap V2")
        
        assert result is not None
        assert result.name == "Uniswap V2"

    def test_case_insensitive(self):
        """Test case-insensitive search."""
        result = get_fingerprint_by_name("uniswap v2")
        
        assert result is not None
        assert result.name == "Uniswap V2"

    def test_not_found(self):
        """Test when fingerprint is not found."""
        result = get_fingerprint_by_name("NonExistent")
        
        assert result is None


# =============================================================================
# get_fingerprints_by_category Tests
# =============================================================================

class TestGetFingerprintsByCategory:
    """Test get_fingerprints_by_category function."""

    def test_find_by_category(self):
        """Test finding fingerprints by category."""
        results = get_fingerprints_by_category("AMM")
        
        assert len(results) > 0
        for fp in results:
            assert fp.category == "AMM"

    def test_case_insensitive(self):
        """Test case-insensitive search."""
        results_lower = get_fingerprints_by_category("amm")
        results_upper = get_fingerprints_by_category("AMM")
        
        assert len(results_lower) == len(results_upper)

    def test_no_results(self):
        """Test when no fingerprints match category."""
        results = get_fingerprints_by_category("NonExistentCategory")
        
        assert results == []


# =============================================================================
# Data Integrity Tests
# =============================================================================

class TestDataIntegrity:
    """Test data integrity of protocol fingerprints."""

    def test_all_protocols_have_functions(self):
        """Test that all protocols have function signatures."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            assert len(fp.function_signatures) > 0, \
                f"{fp.name} has empty function_signatures"

    def test_all_protocols_have_events(self):
        """Test that all protocols have event signatures."""
        fingerprints = get_default_fingerprints()
        
        for fp in fingerprints:
            assert len(fp.event_signatures) > 0, \
                f"{fp.name} has empty event_signatures"

    def test_all_vulnerabilities_have_severity(self):
        """Test that all vulnerabilities have valid severity."""
        fingerprints = get_default_fingerprints()
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        
        for fp in fingerprints:
            for vuln in fp.known_vulnerabilities:
                assert vuln["severity"] in valid_severities, \
                    f"{fp.name} vulnerability {vuln['id']} has invalid severity"

    def test_no_duplicate_protocol_names(self):
        """Test that there are no duplicate protocol names."""
        fingerprints = get_default_fingerprints()
        names = [fp.name for fp in fingerprints]
        
        assert len(names) == len(set(names)), \
            "Duplicate protocol names found"

    def test_vulnerability_ids_unique(self):
        """Test that vulnerability IDs are unique across protocols."""
        fingerprints = get_default_fingerprints()
        all_ids = []
        
        for fp in fingerprints:
            for vuln in fp.known_vulnerabilities:
                all_ids.append(vuln["id"])
        
        assert len(all_ids) == len(set(all_ids)), \
            "Duplicate vulnerability IDs found"
