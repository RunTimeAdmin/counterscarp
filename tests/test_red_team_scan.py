"""
Tests for the red_team_scan module.
"""

import pytest
import sys
import os
import json
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exceptions import SentinelAnalysisError
from red_team_scan import (
    run_slither,
    validate_slither_output,
    filter_vulnerabilities,
    parse_location,
    print_report,
    DEFAULT_SEVERITY_ALLOWLIST,
    DEFAULT_IGNORE_CHECKS,
)


class TestValidateSlitherOutput:
    """Test validate_slither_output() with valid/invalid data."""

    def test_valid_output_returns_true(self):
        """Test valid Slither output returns True."""
        data = {
            "results": {
                "detectors": []
            }
        }
        assert validate_slither_output(data) is True

    def test_none_output_returns_false(self):
        """Test None output returns False."""
        assert validate_slither_output(None) is False

    def test_non_dict_output_returns_false(self):
        """Test non-dict output returns False."""
        assert validate_slither_output("string") is False
        assert validate_slither_output(123) is False
        assert validate_slither_output([]) is False

    def test_missing_results_key_returns_false(self):
        """Test missing 'results' key returns False."""
        data = {"other_key": "value"}
        assert validate_slither_output(data) is False

    def test_results_not_dict_returns_false(self):
        """Test 'results' not being a dict returns False."""
        data = {"results": "not a dict"}
        assert validate_slither_output(data) is False

    def test_no_detectors_is_valid(self):
        """Test output with no detectors is valid (just no findings)."""
        data = {"results": {}}
        assert validate_slither_output(data) is True

    def test_with_errors_in_results(self):
        """Test output with errors in results is still valid."""
        data = {
            "results": {
                "detectors": [],
                "errors": ["some error"]
            }
        }
        assert validate_slither_output(data) is True


class TestFilterVulnerabilities:
    """Test filter_vulnerabilities() with different impact levels."""

    def test_filters_by_severity_allowlist(self):
        """Test filtering by severity allowlist."""
        data = {
            "results": {
                "detectors": [
                    {"check": "high-issue", "impact": "High", "description": "High severity"},
                    {"check": "medium-issue", "impact": "Medium", "description": "Medium severity"},
                    {"check": "low-issue", "impact": "Low", "description": "Low severity"},
                    {"check": "info-issue", "impact": "Informational", "description": "Info"},
                ]
            }
        }
        
        result = filter_vulnerabilities(data)
        
        # Should only include High and Medium
        assert len(result) == 2
        check_ids = {r["title"] for r in result}
        assert "high-issue" in check_ids
        assert "medium-issue" in check_ids

    def test_filters_by_ignore_list(self):
        """Test filtering by ignore list."""
        data = {
            "results": {
                "detectors": [
                    {"check": "solc-version", "impact": "High", "description": "Old solc"},
                    {"check": "reentrancy", "impact": "High", "description": "Reentrancy"},
                ]
            }
        }
        
        result = filter_vulnerabilities(data)
        
        # Should filter out solc-version
        assert len(result) == 1
        assert result[0]["title"] == "reentrancy"

    def test_invalid_output_returns_empty(self):
        """Test invalid output returns empty list."""
        result = filter_vulnerabilities(None)
        assert result == []

    def test_non_dict_output_returns_empty(self):
        """Test non-dict output returns empty list."""
        result = filter_vulnerabilities("invalid")
        assert result == []

    def test_no_detectors_returns_empty(self):
        """Test no detectors returns empty list."""
        data = {"results": {}}
        result = filter_vulnerabilities(data)
        assert result == []

    def test_empty_detectors_returns_empty(self):
        """Test empty detectors list returns empty list."""
        data = {"results": {"detectors": []}}
        result = filter_vulnerabilities(data)
        assert result == []

    def test_preserves_location_info(self):
        """Test location info is preserved in filtered results."""
        data = {
            "results": {
                "detectors": [
                    {
                        "check": "test",
                        "impact": "High",
                        "description": "Test issue",
                        "elements": [
                            {
                                "source_mapping": {
                                    "filename_short": "test.sol",
                                    "lines": [10, 11]
                                }
                            }
                        ]
                    }
                ]
            }
        }
        
        result = filter_vulnerabilities(data)
        
        assert len(result) == 1
        assert "test.sol" in result[0]["location"]


class TestParseLocation:
    """Test parse_location() function."""

    def test_empty_elements_returns_unknown(self):
        """Test empty elements returns unknown location."""
        result = parse_location([])
        assert result == "Unknown location"

    def test_parses_filename_and_lines(self):
        """Test parsing filename and line numbers."""
        elements = [
            {
                "source_mapping": {
                    "filename_short": "test.sol",
                    "lines": [10, 11, 12]
                }
            }
        ]
        
        result = parse_location(elements)
        
        assert "test.sol" in result
        assert "10" in result

    def test_parses_filename_only(self):
        """Test parsing when only filename available."""
        elements = [
            {
                "source_mapping": {
                    "filename_short": "contract.sol"
                }
            }
        ]
        
        result = parse_location(elements)
        
        assert result == "contract.sol"

    def test_missing_source_mapping(self):
        """Test handling missing source_mapping."""
        elements = [
            {"other_key": "value"}
        ]
        
        result = parse_location(elements)
        
        assert "unknown" in result.lower()


class TestRunSlither:
    """Test run_slither() with mocked subprocess."""

    @patch('subprocess.run')
    def test_run_slither_success(self, mock_run):
        """Test successful Slither execution."""
        mock_run.return_value = Mock(
            stdout='{"results": {"detectors": []}}',
            stderr='',
            returncode=0
        )
        
        result = run_slither("test.sol")
        
        assert "results" in result

    @patch('subprocess.run')
    def test_run_slither_with_json_in_output(self, mock_run):
        """Test extracting JSON from mixed output."""
        mock_run.return_value = Mock(
            stdout='Some log output\n{"results": {"detectors": []}}',
            stderr='',
            returncode=0
        )
        
        result = run_slither("test.sol")
        
        assert "results" in result

    @patch('subprocess.run')
    def test_run_slither_no_json_found(self, mock_run):
        """Test handling when no JSON found in output."""
        mock_run.return_value = Mock(
            stdout='Error: compilation failed',
            stderr='Compilation error',
            returncode=1
        )

        with pytest.raises(SentinelAnalysisError) as exc_info:
            run_slither("test.sol")

        assert "slither" in str(exc_info.value).lower()

    @patch('subprocess.run')
    def test_run_slither_not_found(self, mock_run):
        """Test handling when Slither not installed."""
        mock_run.side_effect = FileNotFoundError("slither not found")
        
        with pytest.raises(Exception) as exc_info:
            run_slither("test.sol")
        
        assert "not found" in str(exc_info.value).lower() or "slither" in str(exc_info.value).lower()

    @patch('subprocess.run')
    def test_run_slither_json_decode_error(self, mock_run):
        """Test handling invalid JSON output."""
        mock_run.return_value = Mock(
            stdout='Not valid JSON',
            stderr='',
            returncode=0
        )

        # Function may raise exception or call sys.exit
        with pytest.raises((Exception, SystemExit)):
            run_slither("test.sol")


class TestPrintReport:
    """Test print_report() function."""

    def test_print_no_findings(self, capsys):
        """Test report shows clean message when no findings."""
        print_report([])
        captured = capsys.readouterr()
        
        assert "CLEAN" in captured.out or "No critical" in captured.out

    def test_print_findings(self, capsys):
        """Test report shows findings correctly."""
        findings = [
            {
                "title": "Reentrancy",
                "impact": "High",
                "description": "Reentrancy vulnerability detected",
                "location": "test.sol:10"
            }
        ]
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "Reentrancy" in captured.out
        assert "High" in captured.out
        assert "test.sol" in captured.out

    def test_print_multiple_findings(self, capsys):
        """Test report shows multiple findings."""
        findings = [
            {
                "title": "Reentrancy",
                "impact": "High",
                "description": "Reentrancy",
                "location": "test.sol:10"
            },
            {
                "title": "Unchecked Transfer",
                "impact": "Medium",
                "description": "Unchecked",
                "location": "test.sol:20"
            }
        ]
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "Reentrancy" in captured.out
        assert "Unchecked Transfer" in captured.out


class TestConstants:
    """Test module constants."""

    def test_severity_allowlist(self):
        """Test DEFAULT_SEVERITY_ALLOWLIST contains expected values."""
        assert "High" in DEFAULT_SEVERITY_ALLOWLIST
        assert "Medium" in DEFAULT_SEVERITY_ALLOWLIST
        assert "Low" not in DEFAULT_SEVERITY_ALLOWLIST

    def test_ignore_checks(self):
        """Test DEFAULT_IGNORE_CHECKS contains expected values."""
        assert "solc-version" in DEFAULT_IGNORE_CHECKS
        assert "naming-convention" in DEFAULT_IGNORE_CHECKS
        assert "assembly" in DEFAULT_IGNORE_CHECKS
