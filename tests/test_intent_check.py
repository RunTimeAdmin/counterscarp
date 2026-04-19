"""
Tests for the intent_check module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intent_check import (
    Severity,
    FunctionCategory,
    ModifierType,
    NatSpecInfo,
    ModifierInfo,
    FunctionInfo,
    IntentFinding,
    ModifierClassifier,
    NatSpecParser,
    FunctionParser,
    IntentComparator,
    NatSpecAnalyzer,
    analyze_intent,
    TRUST_KEYWORDS,
    AUTH_MODIFIERS,
)


class TestNatSpecExtraction:
    """Test NatSpec extraction (/// and /** */ formats)."""

    def test_parse_single_line_natspec(self):
        """Test parsing /// style NatSpec comments."""
        comment = """/// @notice Transfer tokens to another address
/// @param to The recipient address
/// @param amount The amount to transfer
/// @return success Whether the transfer succeeded"""

        info = NatSpecParser.parse(comment)

        assert info.notice == "Transfer tokens to another address"
        assert info.params["to"] == "The recipient address"
        assert info.params["amount"] == "The amount to transfer"
        # Parser includes the return variable name in the returns field
        assert "Whether the transfer succeeded" in info.returns

    def test_parse_multiline_natspec(self):
        """Test parsing /** */ style NatSpec comments."""
        comment = """/**
 * @notice Transfer tokens to another address
 * @param to The recipient address
 * @return success Whether the transfer succeeded
 */"""

        info = NatSpecParser.parse(comment)

        assert info.notice == "Transfer tokens to another address"
        assert info.params["to"] == "The recipient address"
        # Parser includes the return variable name in the returns field
        assert "Whether the transfer succeeded" in info.returns

    def test_parse_dev_tag(self):
        """Test parsing @dev tag."""
        comment = """/// @notice Public function
/// @dev Anyone can call this function"""
        
        info = NatSpecParser.parse(comment)
        
        assert info.dev == "Anyone can call this function"

    def test_extract_comment_block_single_line(self):
        """Test extracting single-line comment block."""
        lines = [
            "/// @notice First line",
            "/// @dev Second line",
            "function test() {}",
        ]
        
        comment, end_idx = NatSpecParser.extract_comment_block(lines, 0)
        
        assert "@notice" in comment
        assert "@dev" in comment
        assert end_idx == 1

    def test_extract_comment_block_multiline(self):
        """Test extracting multi-line comment block."""
        lines = [
            "/**",
            " * @notice First line",
            " * @dev Second line",
            " */",
            "function test() {}",
        ]
        
        comment, end_idx = NatSpecParser.extract_comment_block(lines, 0)
        
        assert "@notice" in comment
        assert "*/" in comment
        assert end_idx == 3


class TestModifierClassification:
    """Test modifier classification (access control, reentrancy, pause)."""

    def test_classify_access_control_modifiers(self):
        """Test classification of access control modifiers."""
        assert ModifierClassifier.classify("onlyOwner") == ModifierType.ACCESS_CONTROL
        assert ModifierClassifier.classify("onlyRole") == ModifierType.ACCESS_CONTROL
        assert ModifierClassifier.classify("onlyAdmin") == ModifierType.ACCESS_CONTROL
        assert ModifierClassifier.classify("auth") == ModifierType.ACCESS_CONTROL

    def test_classify_reentrancy_modifiers(self):
        """Test classification of reentrancy protection modifiers."""
        assert ModifierClassifier.classify("nonReentrant") == ModifierType.REENTRANCY_PROTECTION
        assert ModifierClassifier.classify("non_reentrant") == ModifierType.REENTRANCY_PROTECTION
        assert ModifierClassifier.classify("ReentrancyGuard") == ModifierType.REENTRANCY_PROTECTION

    def test_classify_pause_modifiers(self):
        """Test classification of pause control modifiers."""
        assert ModifierClassifier.classify("whenNotPaused") == ModifierType.PAUSE_CONTROL
        assert ModifierClassifier.classify("when_not_paused") == ModifierType.PAUSE_CONTROL
        assert ModifierClassifier.classify("pausable") == ModifierType.PAUSE_CONTROL

    def test_classify_custom_modifiers(self):
        """Test classification of custom modifiers."""
        assert ModifierClassifier.classify("myCustomModifier") == ModifierType.CUSTOM
        assert ModifierClassifier.classify("validationCheck") == ModifierType.CUSTOM


class TestMismatchDetection:
    """Test mismatch detection (NatSpec claims vs actual behavior)."""

    def test_detects_missing_access_control(self):
        """Test detection of claimed restriction without access control."""
        natspec = NatSpecInfo(
            notice="Only owner can withdraw",
            raw="/// @notice Only owner can withdraw"
        )
        func = FunctionInfo(
            name="withdraw",
            line_no=10,
            visibility="external",
            state_mutability=None,
            modifiers=[],
            natspec=natspec
        )
        
        findings = IntentComparator.compare(func, "test.sol")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "access control" in findings[0].description.lower()

    def test_detects_claimed_public_with_access_control(self):
        """Test detection of claimed public access with access control."""
        natspec = NatSpecInfo(
            notice="Anyone can call this function",
            raw="/// @notice Anyone can call this function"
        )
        func = FunctionInfo(
            name="restricted",
            line_no=10,
            visibility="external",
            state_mutability=None,
            modifiers=[ModifierInfo("onlyOwner", ModifierType.ACCESS_CONTROL)],
            natspec=natspec
        )
        
        findings = IntentComparator.compare(func, "test.sol")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_detects_view_mismatch(self):
        """Test detection of claimed view that modifies state."""
        natspec = NatSpecInfo(
            notice="Returns the current balance",
            raw="/// @notice Returns the current balance"
        )
        func = FunctionInfo(
            name="getBalance",
            line_no=10,
            visibility="external",
            state_mutability=None,  # Not view/pure
            modifiers=[],
            natspec=natspec
        )
        
        findings = IntentComparator.compare(func, "test.sol")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "view" in findings[0].claimed_behavior.lower()

    def test_no_mismatch_when_correct(self):
        """Test no finding when NatSpec matches implementation."""
        natspec = NatSpecInfo(
            notice="Only owner can withdraw",
            raw="/// @notice Only owner can withdraw"
        )
        func = FunctionInfo(
            name="withdraw",
            line_no=10,
            visibility="external",
            state_mutability=None,
            modifiers=[ModifierInfo("onlyOwner", ModifierType.ACCESS_CONTROL)],
            natspec=natspec
        )
        
        findings = IntentComparator.compare(func, "test.sol")
        
        assert len(findings) == 0

    def test_detects_internal_with_external_docs(self):
        """Test detection of internal function with external-facing docs."""
        natspec = NatSpecInfo(
            notice="Users can call this to get rewards",
            raw="/// @notice Users can call this to get rewards"
        )
        func = FunctionInfo(
            name="_distributeRewards",
            line_no=10,
            visibility="internal",
            state_mutability=None,
            modifiers=[],
            natspec=natspec
        )
        
        findings = IntentComparator.compare(func, "test.sol")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW


class TestFunctionCategorization:
    """Test function categorization."""

    def test_pure_function_category(self):
        """Test pure function gets PURE category."""
        func = FunctionInfo(
            name="calculate",
            line_no=10,
            visibility="public",
            state_mutability="pure",
            modifiers=[],
            natspec=None
        )
        
        categories = func.get_categories()
        
        assert FunctionCategory.PURE in categories

    def test_view_function_category(self):
        """Test view function gets VIEW category."""
        func = FunctionInfo(
            name="getBalance",
            line_no=10,
            visibility="public",
            state_mutability="view",
            modifiers=[],
            natspec=None
        )
        
        categories = func.get_categories()
        
        assert FunctionCategory.VIEW in categories

    def test_payable_function_category(self):
        """Test payable function gets PAYABLE category."""
        func = FunctionInfo(
            name="deposit",
            line_no=10,
            visibility="external",
            state_mutability="payable",
            modifiers=[],
            natspec=None
        )
        
        categories = func.get_categories()
        
        assert FunctionCategory.PAYABLE in categories

    def test_access_controlled_category(self):
        """Test function with access control gets correct categories."""
        func = FunctionInfo(
            name="adminFunc",
            line_no=10,
            visibility="external",
            state_mutability=None,
            modifiers=[ModifierInfo("onlyOwner", ModifierType.ACCESS_CONTROL)],
            natspec=None
        )
        
        categories = func.get_categories()
        
        assert FunctionCategory.ACCESS_CONTROLLED in categories
        assert FunctionCategory.ADMINISTRATIVE in categories

    def test_internal_function_category(self):
        """Test internal function gets ADMINISTRATIVE category."""
        func = FunctionInfo(
            name="_internal",
            line_no=10,
            visibility="internal",
            state_mutability=None,
            modifiers=[],
            natspec=None
        )
        
        categories = func.get_categories()
        
        assert FunctionCategory.ADMINISTRATIVE in categories


class TestFunctionParser:
    """Test function parsing."""

    def test_parse_simple_function(self):
        """Test parsing simple function definition."""
        line = "function transfer(address to, uint256 amount) external {"
        func = FunctionParser.parse(line, 10)
        
        assert func is not None
        assert func.name == "transfer"
        assert func.visibility == "external"
        assert func.line_no == 10

    def test_parse_function_with_modifiers(self):
        """Test parsing function with modifiers."""
        line = "function mint(address to) public onlyOwner nonReentrant {"
        func = FunctionParser.parse(line, 10)
        
        assert func is not None
        assert func.name == "mint"
        mod_names = [m.name for m in func.modifiers]
        assert "onlyOwner" in mod_names
        assert "nonReentrant" in mod_names

    def test_parse_view_function(self):
        """Test parsing view function."""
        line = "function balanceOf(address account) public view returns (uint256) {"
        func = FunctionParser.parse(line, 10)
        
        assert func is not None
        assert func.state_mutability == "view"

    def test_parse_pure_function(self):
        """Test parsing pure function."""
        line = "function calculate(uint256 a) public pure returns (uint256) {"
        func = FunctionParser.parse(line, 10)
        
        assert func is not None
        assert func.state_mutability == "pure"

    def test_parse_payable_function(self):
        """Test parsing payable function."""
        line = "function deposit() external payable {"
        func = FunctionParser.parse(line, 10)
        
        assert func is not None
        assert func.state_mutability == "payable"

    def test_parse_non_function_returns_none(self):
        """Test parsing non-function line returns None."""
        line = "uint256 public balance;"
        func = FunctionParser.parse(line, 10)
        
        assert func is None


class TestNatSpecAnalyzer:
    """Test NatSpecAnalyzer integration."""

    def test_analyze_file_with_mismatches(self, tmp_path):
        """Test analyzing file with intent mismatches."""
        contract = '''
pragma solidity ^0.8.0;

contract Test {
    /// @notice Only owner can withdraw
    function withdraw() external {
        // No access control!
    }
}
'''
        contract_file = tmp_path / "Test.sol"
        contract_file.write_text(contract)
        
        analyzer = NatSpecAnalyzer()
        findings = analyzer.analyze_file(str(contract_file))
        
        assert len(findings) == 1
        assert findings[0].function_name == "withdraw"

    def test_analyze_file_no_mismatches(self, tmp_path):
        """Test analyzing file without intent mismatches."""
        contract = '''
pragma solidity ^0.8.0;

contract Test {
    /// @notice Only owner can withdraw
    function withdraw() external onlyOwner {
        // Proper access control
    }
}
'''
        contract_file = tmp_path / "Test.sol"
        contract_file.write_text(contract)
        
        analyzer = NatSpecAnalyzer()
        findings = analyzer.analyze_file(str(contract_file))
        
        # Should have no mismatches
        assert len(findings) == 0

    def test_analyze_directory(self, tmp_path):
        """Test analyzing directory with multiple files."""
        (tmp_path / "File1.sol").write_text('''
pragma solidity ^0.8.0;
contract C1 {
    /// @notice Only owner
    function f1() external {}
}
''')
        (tmp_path / "File2.sol").write_text('''
pragma solidity ^0.8.0;
contract C2 {
    /// @notice Only owner
    function f2() external {}
}
''')
        
        analyzer = NatSpecAnalyzer()
        findings = analyzer.analyze_directory(str(tmp_path))
        
        # Should find mismatches in both files
        assert len(findings) == 2

    def test_analyze_file_not_found(self):
        """Test analyzing nonexistent file raises error."""
        analyzer = NatSpecAnalyzer()
        
        with pytest.raises(Exception):
            analyzer.analyze_file("/nonexistent/file.sol")


class TestAnalyzeIntent:
    """Test analyze_intent entry point."""

    def test_analyze_intent_returns_list(self, tmp_path):
        """Test analyze_intent returns list of findings."""
        contract = '''
pragma solidity ^0.8.0;

contract Test {
    /// @notice Only owner can call this
    function restricted() external {
        // Missing access control
    }
}
'''
        contract_file = tmp_path / "Test.sol"
        contract_file.write_text(contract)
        
        findings = analyze_intent(str(contract_file), verbose=False)
        
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert "function_name" in findings[0]
        assert findings[0]["function_name"] == "restricted"

    def test_analyze_intent_empty_findings(self, tmp_path):
        """Test analyze_intent returns empty list when no issues."""
        contract = '''
pragma solidity ^0.8.0;

contract Test {
    /// @notice Anyone can call this
    function publicFunc() external {
        // Correctly public
    }
}
'''
        contract_file = tmp_path / "Test.sol"
        contract_file.write_text(contract)
        
        findings = analyze_intent(str(contract_file), verbose=False)
        
        assert findings == []


class TestNatSpecClaims:
    """Test NatSpec claim detection methods."""

    def test_claims_public_access(self):
        """Test detection of public access claims."""
        info = NatSpecInfo(notice="Anyone can call this function")
        assert info.claims_public_access() is True
        
        info2 = NatSpecInfo(notice="Only owner can call")
        assert info2.claims_public_access() is False

    def test_claims_restricted_access(self):
        """Test detection of restricted access claims."""
        info = NatSpecInfo(notice="Only owner can call this function")
        assert info.claims_restricted_access() is True
        
        info2 = NatSpecInfo(notice="Anyone can call")
        assert info2.claims_restricted_access() is False

    def test_claims_view_behavior(self):
        """Test detection of view behavior claims."""
        info = NatSpecInfo(notice="Returns the current balance")
        assert info.claims_view_behavior() is True
        
        info2 = NatSpecInfo(notice="Updates the state")
        assert info2.claims_view_behavior() is False

    def test_claims_state_modification(self):
        """Test detection of state modification claims."""
        info = NatSpecInfo(notice="Updates the balance")
        assert info.claims_state_modification() is True
        
        info2 = NatSpecInfo(notice="Returns the balance")
        assert info2.claims_state_modification() is False


class TestIntentFinding:
    """Test IntentFinding dataclass."""

    def test_to_dict_serialization(self):
        """Test IntentFinding to_dict method."""
        finding = IntentFinding(
            function_name="test",
            file_path="test.sol",
            line_no=10,
            severity=Severity.HIGH,
            claimed_behavior="Restricted",
            actual_behavior="Public",
            description="Test description",
            evidence={"key": "value"}
        )
        
        d = finding.to_dict()
        
        assert d["function_name"] == "test"
        assert d["severity"] == "High"
        assert d["evidence"]["key"] == "value"


class TestLegacyConstants:
    """Test legacy constants for backward compatibility."""

    def test_trust_keywords_defined(self):
        """Test TRUST_KEYWORDS constant."""
        assert "admin" in TRUST_KEYWORDS
        assert "owner" in TRUST_KEYWORDS
        assert "restrict" in TRUST_KEYWORDS
        assert "protected" in TRUST_KEYWORDS

    def test_auth_modifiers_defined(self):
        """Test AUTH_MODIFIERS constant."""
        assert "onlyOwner" in AUTH_MODIFIERS
        assert "onlyRole" in AUTH_MODIFIERS
        assert "nonReentrant" in AUTH_MODIFIERS
