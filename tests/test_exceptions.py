"""
Tests for the exceptions module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exceptions import (
    GarrisonError,
    GarrisonConfigError,
    GarrisonAnalysisError,
    GarrisonAPIError,
    GarrisonReportError,
    GarrisonToolNotFoundError,
    GarrisonValidationError,
    GarrisonTimeoutError,
    format_exception_chain,
    is_garrison_error,
)


class TestGarrisonError:
    """Test base GarrisonError class."""

    def test_creation_with_message(self):
        """Test exception can be created with message."""
        exc = GarrisonError("Test error message")
        assert str(exc) == "Test error message"
        assert exc.message == "Test error message"

    def test_creation_with_details(self):
        """Test exception can be created with details."""
        exc = GarrisonError(
            "Test error",
            details={"key": "value", "code": 500}
        )
        assert exc.details["key"] == "value"
        assert exc.details["code"] == 500

    def test_str_with_details(self):
        """Test string representation includes details."""
        exc = GarrisonError(
            "Test error",
            details={"path": "/test"}
        )
        str_repr = str(exc)
        assert "Test error" in str_repr
        assert "path" in str_repr

    def test_str_without_details(self):
        """Test string representation without details."""
        exc = GarrisonError("Simple error")
        assert str(exc) == "Simple error"

    def test_to_dict_basic(self):
        """Test to_dict with basic error."""
        exc = GarrisonError("Test error")
        d = exc.to_dict()
        assert d["type"] == "GarrisonError"
        assert d["message"] == "Test error"

    def test_to_dict_with_details(self):
        """Test to_dict includes details."""
        exc = GarrisonError("Test", details={"code": 500})
        d = exc.to_dict()
        assert d["details"]["code"] == 500

    def test_to_dict_with_cause(self):
        """Test to_dict includes cause when chained."""
        original = ValueError("Original error")
        exc = GarrisonError("Wrapped error")
        exc.__cause__ = original
        d = exc.to_dict()
        assert "cause" in d
        assert "Original error" in d["cause"]


class TestGarrisonConfigError:
    """Test GarrisonConfigError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonConfigError(
            "Config load failed",
            details={"path": "config.toml", "line": 10}
        )
        assert exc.message == "Config load failed"
        assert exc.details["path"] == "config.toml"

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonConfigError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonAnalysisError:
    """Test GarrisonAnalysisError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonAnalysisError(
            "Slither failed",
            details={"tool": "slither", "contract": "test.sol"}
        )
        assert exc.message == "Slither failed"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonAnalysisError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonAPIError:
    """Test GarrisonAPIError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonAPIError(
            "OSV API failed",
            details={"status_code": 503, "endpoint": "/v1/query"}
        )
        assert exc.message == "OSV API failed"
        assert exc.details["status_code"] == 503

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonAPIError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonReportError:
    """Test GarrisonReportError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonReportError(
            "Failed to write report",
            details={"format": "html", "output_path": "/reports"}
        )
        assert exc.message == "Failed to write report"
        assert exc.details["format"] == "html"

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonReportError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonToolNotFoundError:
    """Test GarrisonToolNotFoundError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonToolNotFoundError(
            "Slither not found",
            details={"tool": "slither", "install_cmd": "pip install slither"}
        )
        assert exc.message == "Slither not found"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonToolNotFoundError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonValidationError:
    """Test GarrisonValidationError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonValidationError(
            "Invalid input",
            details={"field": "address", "value": "0x123"}
        )
        assert exc.message == "Invalid input"
        assert exc.details["field"] == "address"

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonValidationError("Test")
        assert isinstance(exc, GarrisonError)


class TestGarrisonTimeoutError:
    """Test GarrisonTimeoutError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = GarrisonTimeoutError(
            "Analysis timed out",
            details={"operation": "fuzzing", "timeout_seconds": 300}
        )
        assert exc.message == "Analysis timed out"
        assert exc.details["timeout_seconds"] == 300

    def test_inheritance(self):
        """Test inheritance from GarrisonError."""
        exc = GarrisonTimeoutError("Test")
        assert isinstance(exc, GarrisonError)


class TestExceptionChaining:
    """Test exception chaining behavior."""

    def test_explicit_chaining(self):
        """Test explicit exception chaining with 'from'."""
        original = ValueError("Original error")
        exc = GarrisonConfigError("Config failed")
        exc.__cause__ = original
        assert exc.__cause__ is original
        assert str(exc.__cause__) == "Original error"

    def test_implicit_chaining(self):
        """Test implicit exception chaining in nested try blocks."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError:
                raise GarrisonError("Outer error")
        except GarrisonError as exc:
            # Implicit chaining sets __context__, not __cause__
            # __cause__ is only set with explicit 'from' syntax
            assert exc.__context__ is not None or exc.__cause__ is not None

    def test_to_dict_preserves_cause(self):
        """Test to_dict preserves cause information."""
        try:
            raise RuntimeError("Root cause")
        except RuntimeError as root:
            try:
                raise GarrisonAnalysisError("Analysis failed") from root
            except GarrisonAnalysisError as analysis:
                d = analysis.to_dict()
                assert "cause" in d


class TestFormatExceptionChain:
    """Test format_exception_chain function."""

    def test_single_exception(self):
        """Test formatting single exception."""
        exc = GarrisonError("Single error")
        result = format_exception_chain(exc)
        assert result == "Single error"

    def test_chained_exceptions(self):
        """Test formatting chained exceptions."""
        root = ValueError("Root cause")
        exc = GarrisonError("Wrapped")
        exc.__cause__ = root
        result = format_exception_chain(exc)
        assert "Wrapped" in result
        assert "Caused by" in result
        assert "Root cause" in result

    def test_triple_chained_exceptions(self):
        """Test formatting triple chained exceptions."""
        e1 = Exception("Level 1")
        e2 = GarrisonError("Level 2")
        e2.__cause__ = e1
        e3 = GarrisonConfigError("Level 3")
        e3.__cause__ = e2
        result = format_exception_chain(e3)
        assert "Level 3" in result
        assert "Level 2" in result
        assert "Level 1" in result


class TestIsGarrisonError:
    """Test is_garrison_error function."""

    def test_garrison_error_returns_true(self):
        """Test GarrisonError returns True."""
        exc = GarrisonError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_config_error_returns_true(self):
        """Test GarrisonConfigError returns True."""
        exc = GarrisonConfigError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_analysis_error_returns_true(self):
        """Test GarrisonAnalysisError returns True."""
        exc = GarrisonAnalysisError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_api_error_returns_true(self):
        """Test GarrisonAPIError returns True."""
        exc = GarrisonAPIError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_report_error_returns_true(self):
        """Test GarrisonReportError returns True."""
        exc = GarrisonReportError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_tool_not_found_error_returns_true(self):
        """Test GarrisonToolNotFoundError returns True."""
        exc = GarrisonToolNotFoundError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_validation_error_returns_true(self):
        """Test GarrisonValidationError returns True."""
        exc = GarrisonValidationError("Test")
        assert is_garrison_error(exc) is True

    def test_garrison_timeout_error_returns_true(self):
        """Test GarrisonTimeoutError returns True."""
        exc = GarrisonTimeoutError("Test")
        assert is_garrison_error(exc) is True

    def test_value_error_returns_false(self):
        """Test ValueError returns False."""
        exc = ValueError("Test")
        assert is_garrison_error(exc) is False

    def test_runtime_error_returns_false(self):
        """Test RuntimeError returns False."""
        exc = RuntimeError("Test")
        assert is_garrison_error(exc) is False

    def test_type_error_returns_false(self):
        """Test TypeError returns False."""
        exc = TypeError("Test")
        assert is_garrison_error(exc) is False


class TestAllExceptionTypes:
    """Test all exception types can be created."""

    def test_all_types_with_message(self):
        """Test all exception types can be created with message."""
        exceptions = [
            GarrisonError("Base"),
            GarrisonConfigError("Config"),
            GarrisonAnalysisError("Analysis"),
            GarrisonAPIError("API"),
            GarrisonReportError("Report"),
            GarrisonToolNotFoundError("Tool"),
            GarrisonValidationError("Validation"),
            GarrisonTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            assert isinstance(exc, GarrisonError)
            assert exc.message is not None

    def test_all_types_with_details(self):
        """Test all exception types can be created with details."""
        exceptions = [
            GarrisonError("Base", {"code": 1}),
            GarrisonConfigError("Config", {"file": "test"}),
            GarrisonAnalysisError("Analysis", {"tool": "slither"}),
            GarrisonAPIError("API", {"status": 500}),
            GarrisonReportError("Report", {"format": "html"}),
            GarrisonToolNotFoundError("Tool", {"tool": "mythril"}),
            GarrisonValidationError("Validation", {"field": "address"}),
            GarrisonTimeoutError("Timeout", {"seconds": 30}),
        ]
        
        for exc in exceptions:
            assert len(exc.details) > 0

    def test_all_types_to_dict(self):
        """Test all exception types can be serialized to dict."""
        exceptions = [
            GarrisonError("Base"),
            GarrisonConfigError("Config"),
            GarrisonAnalysisError("Analysis"),
            GarrisonAPIError("API"),
            GarrisonReportError("Report"),
            GarrisonToolNotFoundError("Tool"),
            GarrisonValidationError("Validation"),
            GarrisonTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            d = exc.to_dict()
            assert "type" in d
            assert "message" in d
            assert d["type"] == exc.__class__.__name__
