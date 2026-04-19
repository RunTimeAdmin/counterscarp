"""
Tests for the exceptions module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exceptions import (
    SentinelError,
    SentinelConfigError,
    SentinelAnalysisError,
    SentinelAPIError,
    SentinelReportError,
    SentinelToolNotFoundError,
    SentinelValidationError,
    SentinelTimeoutError,
    format_exception_chain,
    is_sentinel_error,
)


class TestSentinelError:
    """Test base SentinelError class."""

    def test_creation_with_message(self):
        """Test exception can be created with message."""
        exc = SentinelError("Test error message")
        assert str(exc) == "Test error message"
        assert exc.message == "Test error message"

    def test_creation_with_details(self):
        """Test exception can be created with details."""
        exc = SentinelError(
            "Test error",
            details={"key": "value", "code": 500}
        )
        assert exc.details["key"] == "value"
        assert exc.details["code"] == 500

    def test_str_with_details(self):
        """Test string representation includes details."""
        exc = SentinelError(
            "Test error",
            details={"path": "/test"}
        )
        str_repr = str(exc)
        assert "Test error" in str_repr
        assert "path" in str_repr

    def test_str_without_details(self):
        """Test string representation without details."""
        exc = SentinelError("Simple error")
        assert str(exc) == "Simple error"

    def test_to_dict_basic(self):
        """Test to_dict with basic error."""
        exc = SentinelError("Test error")
        d = exc.to_dict()
        assert d["type"] == "SentinelError"
        assert d["message"] == "Test error"

    def test_to_dict_with_details(self):
        """Test to_dict includes details."""
        exc = SentinelError("Test", details={"code": 500})
        d = exc.to_dict()
        assert d["details"]["code"] == 500

    def test_to_dict_with_cause(self):
        """Test to_dict includes cause when chained."""
        original = ValueError("Original error")
        exc = SentinelError("Wrapped error")
        exc.__cause__ = original
        d = exc.to_dict()
        assert "cause" in d
        assert "Original error" in d["cause"]


class TestSentinelConfigError:
    """Test SentinelConfigError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelConfigError(
            "Config load failed",
            details={"path": "config.toml", "line": 10}
        )
        assert exc.message == "Config load failed"
        assert exc.details["path"] == "config.toml"

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelConfigError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelAnalysisError:
    """Test SentinelAnalysisError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelAnalysisError(
            "Slither failed",
            details={"tool": "slither", "contract": "test.sol"}
        )
        assert exc.message == "Slither failed"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelAnalysisError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelAPIError:
    """Test SentinelAPIError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelAPIError(
            "OSV API failed",
            details={"status_code": 503, "endpoint": "/v1/query"}
        )
        assert exc.message == "OSV API failed"
        assert exc.details["status_code"] == 503

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelAPIError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelReportError:
    """Test SentinelReportError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelReportError(
            "Failed to write report",
            details={"format": "html", "output_path": "/reports"}
        )
        assert exc.message == "Failed to write report"
        assert exc.details["format"] == "html"

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelReportError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelToolNotFoundError:
    """Test SentinelToolNotFoundError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelToolNotFoundError(
            "Slither not found",
            details={"tool": "slither", "install_cmd": "pip install slither"}
        )
        assert exc.message == "Slither not found"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelToolNotFoundError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelValidationError:
    """Test SentinelValidationError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelValidationError(
            "Invalid input",
            details={"field": "address", "value": "0x123"}
        )
        assert exc.message == "Invalid input"
        assert exc.details["field"] == "address"

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelValidationError("Test")
        assert isinstance(exc, SentinelError)


class TestSentinelTimeoutError:
    """Test SentinelTimeoutError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = SentinelTimeoutError(
            "Analysis timed out",
            details={"operation": "fuzzing", "timeout_seconds": 300}
        )
        assert exc.message == "Analysis timed out"
        assert exc.details["timeout_seconds"] == 300

    def test_inheritance(self):
        """Test inheritance from SentinelError."""
        exc = SentinelTimeoutError("Test")
        assert isinstance(exc, SentinelError)


class TestExceptionChaining:
    """Test exception chaining behavior."""

    def test_explicit_chaining(self):
        """Test explicit exception chaining with 'from'."""
        original = ValueError("Original error")
        exc = SentinelConfigError("Config failed")
        exc.__cause__ = original
        assert exc.__cause__ is original
        assert str(exc.__cause__) == "Original error"

    def test_implicit_chaining(self):
        """Test implicit exception chaining in nested try blocks."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError:
                raise SentinelError("Outer error")
        except SentinelError as exc:
            # Implicit chaining sets __context__, not __cause__
            # __cause__ is only set with explicit 'from' syntax
            assert exc.__context__ is not None or exc.__cause__ is not None

    def test_to_dict_preserves_cause(self):
        """Test to_dict preserves cause information."""
        try:
            raise RuntimeError("Root cause")
        except RuntimeError as root:
            try:
                raise SentinelAnalysisError("Analysis failed") from root
            except SentinelAnalysisError as analysis:
                d = analysis.to_dict()
                assert "cause" in d


class TestFormatExceptionChain:
    """Test format_exception_chain function."""

    def test_single_exception(self):
        """Test formatting single exception."""
        exc = SentinelError("Single error")
        result = format_exception_chain(exc)
        assert result == "Single error"

    def test_chained_exceptions(self):
        """Test formatting chained exceptions."""
        root = ValueError("Root cause")
        exc = SentinelError("Wrapped")
        exc.__cause__ = root
        result = format_exception_chain(exc)
        assert "Wrapped" in result
        assert "Caused by" in result
        assert "Root cause" in result

    def test_triple_chained_exceptions(self):
        """Test formatting triple chained exceptions."""
        e1 = Exception("Level 1")
        e2 = SentinelError("Level 2")
        e2.__cause__ = e1
        e3 = SentinelConfigError("Level 3")
        e3.__cause__ = e2
        result = format_exception_chain(e3)
        assert "Level 3" in result
        assert "Level 2" in result
        assert "Level 1" in result


class TestIsSentinelError:
    """Test is_sentinel_error function."""

    def test_sentinel_error_returns_true(self):
        """Test SentinelError returns True."""
        exc = SentinelError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_config_error_returns_true(self):
        """Test SentinelConfigError returns True."""
        exc = SentinelConfigError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_analysis_error_returns_true(self):
        """Test SentinelAnalysisError returns True."""
        exc = SentinelAnalysisError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_api_error_returns_true(self):
        """Test SentinelAPIError returns True."""
        exc = SentinelAPIError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_report_error_returns_true(self):
        """Test SentinelReportError returns True."""
        exc = SentinelReportError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_tool_not_found_error_returns_true(self):
        """Test SentinelToolNotFoundError returns True."""
        exc = SentinelToolNotFoundError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_validation_error_returns_true(self):
        """Test SentinelValidationError returns True."""
        exc = SentinelValidationError("Test")
        assert is_sentinel_error(exc) is True

    def test_sentinel_timeout_error_returns_true(self):
        """Test SentinelTimeoutError returns True."""
        exc = SentinelTimeoutError("Test")
        assert is_sentinel_error(exc) is True

    def test_value_error_returns_false(self):
        """Test ValueError returns False."""
        exc = ValueError("Test")
        assert is_sentinel_error(exc) is False

    def test_runtime_error_returns_false(self):
        """Test RuntimeError returns False."""
        exc = RuntimeError("Test")
        assert is_sentinel_error(exc) is False

    def test_type_error_returns_false(self):
        """Test TypeError returns False."""
        exc = TypeError("Test")
        assert is_sentinel_error(exc) is False


class TestAllExceptionTypes:
    """Test all exception types can be created."""

    def test_all_types_with_message(self):
        """Test all exception types can be created with message."""
        exceptions = [
            SentinelError("Base"),
            SentinelConfigError("Config"),
            SentinelAnalysisError("Analysis"),
            SentinelAPIError("API"),
            SentinelReportError("Report"),
            SentinelToolNotFoundError("Tool"),
            SentinelValidationError("Validation"),
            SentinelTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            assert isinstance(exc, SentinelError)
            assert exc.message is not None

    def test_all_types_with_details(self):
        """Test all exception types can be created with details."""
        exceptions = [
            SentinelError("Base", {"code": 1}),
            SentinelConfigError("Config", {"file": "test"}),
            SentinelAnalysisError("Analysis", {"tool": "slither"}),
            SentinelAPIError("API", {"status": 500}),
            SentinelReportError("Report", {"format": "html"}),
            SentinelToolNotFoundError("Tool", {"tool": "mythril"}),
            SentinelValidationError("Validation", {"field": "address"}),
            SentinelTimeoutError("Timeout", {"seconds": 30}),
        ]
        
        for exc in exceptions:
            assert len(exc.details) > 0

    def test_all_types_to_dict(self):
        """Test all exception types can be serialized to dict."""
        exceptions = [
            SentinelError("Base"),
            SentinelConfigError("Config"),
            SentinelAnalysisError("Analysis"),
            SentinelAPIError("API"),
            SentinelReportError("Report"),
            SentinelToolNotFoundError("Tool"),
            SentinelValidationError("Validation"),
            SentinelTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            d = exc.to_dict()
            assert "type" in d
            assert "message" in d
            assert d["type"] == exc.__class__.__name__
