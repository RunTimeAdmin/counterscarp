"""
Tests for the exceptions module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exceptions import (
    CounterscarpError,
    CounterscarpConfigError,
    CounterscarpAnalysisError,
    CounterscarpAPIError,
    CounterscarpReportError,
    CounterscarpToolNotFoundError,
    CounterscarpValidationError,
    CounterscarpTimeoutError,
    format_exception_chain,
    is_counterscarp_error,
)


class TestCounterscarpError:
    """Test base CounterscarpError class."""

    def test_creation_with_message(self):
        """Test exception can be created with message."""
        exc = CounterscarpError("Test error message")
        assert str(exc) == "Test error message"
        assert exc.message == "Test error message"

    def test_creation_with_details(self):
        """Test exception can be created with details."""
        exc = CounterscarpError(
            "Test error",
            details={"key": "value", "code": 500}
        )
        assert exc.details["key"] == "value"
        assert exc.details["code"] == 500

    def test_str_with_details(self):
        """Test string representation includes details."""
        exc = CounterscarpError(
            "Test error",
            details={"path": "/test"}
        )
        str_repr = str(exc)
        assert "Test error" in str_repr
        assert "path" in str_repr

    def test_str_without_details(self):
        """Test string representation without details."""
        exc = CounterscarpError("Simple error")
        assert str(exc) == "Simple error"

    def test_to_dict_basic(self):
        """Test to_dict with basic error."""
        exc = CounterscarpError("Test error")
        d = exc.to_dict()
        assert d["type"] == "CounterscarpError"
        assert d["message"] == "Test error"

    def test_to_dict_with_details(self):
        """Test to_dict includes details."""
        exc = CounterscarpError("Test", details={"code": 500})
        d = exc.to_dict()
        assert d["details"]["code"] == 500

    def test_to_dict_with_cause(self):
        """Test to_dict includes cause when chained."""
        original = ValueError("Original error")
        exc = CounterscarpError("Wrapped error")
        exc.__cause__ = original
        d = exc.to_dict()
        assert "cause" in d
        assert "Original error" in d["cause"]


class TestCounterscarpConfigError:
    """Test CounterscarpConfigError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpConfigError(
            "Config load failed",
            details={"path": "config.toml", "line": 10}
        )
        assert exc.message == "Config load failed"
        assert exc.details["path"] == "config.toml"

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpConfigError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpAnalysisError:
    """Test CounterscarpAnalysisError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpAnalysisError(
            "Slither failed",
            details={"tool": "slither", "contract": "test.sol"}
        )
        assert exc.message == "Slither failed"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpAnalysisError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpAPIError:
    """Test CounterscarpAPIError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpAPIError(
            "OSV API failed",
            details={"status_code": 503, "endpoint": "/v1/query"}
        )
        assert exc.message == "OSV API failed"
        assert exc.details["status_code"] == 503

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpAPIError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpReportError:
    """Test CounterscarpReportError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpReportError(
            "Failed to write report",
            details={"format": "html", "output_path": "/reports"}
        )
        assert exc.message == "Failed to write report"
        assert exc.details["format"] == "html"

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpReportError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpToolNotFoundError:
    """Test CounterscarpToolNotFoundError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpToolNotFoundError(
            "Slither not found",
            details={"tool": "slither", "install_cmd": "pip install slither"}
        )
        assert exc.message == "Slither not found"
        assert exc.details["tool"] == "slither"

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpToolNotFoundError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpValidationError:
    """Test CounterscarpValidationError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpValidationError(
            "Invalid input",
            details={"field": "address", "value": "0x123"}
        )
        assert exc.message == "Invalid input"
        assert exc.details["field"] == "address"

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpValidationError("Test")
        assert isinstance(exc, CounterscarpError)


class TestCounterscarpTimeoutError:
    """Test CounterscarpTimeoutError class."""

    def test_creation(self):
        """Test exception creation."""
        exc = CounterscarpTimeoutError(
            "Analysis timed out",
            details={"operation": "fuzzing", "timeout_seconds": 300}
        )
        assert exc.message == "Analysis timed out"
        assert exc.details["timeout_seconds"] == 300

    def test_inheritance(self):
        """Test inheritance from CounterscarpError."""
        exc = CounterscarpTimeoutError("Test")
        assert isinstance(exc, CounterscarpError)


class TestExceptionChaining:
    """Test exception chaining behavior."""

    def test_explicit_chaining(self):
        """Test explicit exception chaining with 'from'."""
        original = ValueError("Original error")
        exc = CounterscarpConfigError("Config failed")
        exc.__cause__ = original
        assert exc.__cause__ is original
        assert str(exc.__cause__) == "Original error"

    def test_implicit_chaining(self):
        """Test implicit exception chaining in nested try blocks."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError:
                raise CounterscarpError("Outer error")
        except CounterscarpError as exc:
            # Implicit chaining sets __context__, not __cause__
            # __cause__ is only set with explicit 'from' syntax
            assert exc.__context__ is not None or exc.__cause__ is not None

    def test_to_dict_preserves_cause(self):
        """Test to_dict preserves cause information."""
        try:
            raise RuntimeError("Root cause")
        except RuntimeError as root:
            try:
                raise CounterscarpAnalysisError("Analysis failed") from root
            except CounterscarpAnalysisError as analysis:
                d = analysis.to_dict()
                assert "cause" in d


class TestFormatExceptionChain:
    """Test format_exception_chain function."""

    def test_single_exception(self):
        """Test formatting single exception."""
        exc = CounterscarpError("Single error")
        result = format_exception_chain(exc)
        assert result == "Single error"

    def test_chained_exceptions(self):
        """Test formatting chained exceptions."""
        root = ValueError("Root cause")
        exc = CounterscarpError("Wrapped")
        exc.__cause__ = root
        result = format_exception_chain(exc)
        assert "Wrapped" in result
        assert "Caused by" in result
        assert "Root cause" in result

    def test_triple_chained_exceptions(self):
        """Test formatting triple chained exceptions."""
        e1 = Exception("Level 1")
        e2 = CounterscarpError("Level 2")
        e2.__cause__ = e1
        e3 = CounterscarpConfigError("Level 3")
        e3.__cause__ = e2
        result = format_exception_chain(e3)
        assert "Level 3" in result
        assert "Level 2" in result
        assert "Level 1" in result


class TestIsCounterscarpError:
    """Test is_counterscarp_error function."""

    def test_counterscarp_error_returns_true(self):
        """Test CounterscarpError returns True."""
        exc = CounterscarpError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_config_error_returns_true(self):
        """Test CounterscarpConfigError returns True."""
        exc = CounterscarpConfigError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_analysis_error_returns_true(self):
        """Test CounterscarpAnalysisError returns True."""
        exc = CounterscarpAnalysisError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_api_error_returns_true(self):
        """Test CounterscarpAPIError returns True."""
        exc = CounterscarpAPIError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_report_error_returns_true(self):
        """Test CounterscarpReportError returns True."""
        exc = CounterscarpReportError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_tool_not_found_error_returns_true(self):
        """Test CounterscarpToolNotFoundError returns True."""
        exc = CounterscarpToolNotFoundError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_validation_error_returns_true(self):
        """Test CounterscarpValidationError returns True."""
        exc = CounterscarpValidationError("Test")
        assert is_counterscarp_error(exc) is True

    def test_counterscarp_timeout_error_returns_true(self):
        """Test CounterscarpTimeoutError returns True."""
        exc = CounterscarpTimeoutError("Test")
        assert is_counterscarp_error(exc) is True

    def test_value_error_returns_false(self):
        """Test ValueError returns False."""
        exc = ValueError("Test")
        assert is_counterscarp_error(exc) is False

    def test_runtime_error_returns_false(self):
        """Test RuntimeError returns False."""
        exc = RuntimeError("Test")
        assert is_counterscarp_error(exc) is False

    def test_type_error_returns_false(self):
        """Test TypeError returns False."""
        exc = TypeError("Test")
        assert is_counterscarp_error(exc) is False


class TestAllExceptionTypes:
    """Test all exception types can be created."""

    def test_all_types_with_message(self):
        """Test all exception types can be created with message."""
        exceptions = [
            CounterscarpError("Base"),
            CounterscarpConfigError("Config"),
            CounterscarpAnalysisError("Analysis"),
            CounterscarpAPIError("API"),
            CounterscarpReportError("Report"),
            CounterscarpToolNotFoundError("Tool"),
            CounterscarpValidationError("Validation"),
            CounterscarpTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            assert isinstance(exc, CounterscarpError)
            assert exc.message is not None

    def test_all_types_with_details(self):
        """Test all exception types can be created with details."""
        exceptions = [
            CounterscarpError("Base", {"code": 1}),
            CounterscarpConfigError("Config", {"file": "test"}),
            CounterscarpAnalysisError("Analysis", {"tool": "slither"}),
            CounterscarpAPIError("API", {"status": 500}),
            CounterscarpReportError("Report", {"format": "html"}),
            CounterscarpToolNotFoundError("Tool", {"tool": "mythril"}),
            CounterscarpValidationError("Validation", {"field": "address"}),
            CounterscarpTimeoutError("Timeout", {"seconds": 30}),
        ]
        
        for exc in exceptions:
            assert len(exc.details) > 0

    def test_all_types_to_dict(self):
        """Test all exception types can be serialized to dict."""
        exceptions = [
            CounterscarpError("Base"),
            CounterscarpConfigError("Config"),
            CounterscarpAnalysisError("Analysis"),
            CounterscarpAPIError("API"),
            CounterscarpReportError("Report"),
            CounterscarpToolNotFoundError("Tool"),
            CounterscarpValidationError("Validation"),
            CounterscarpTimeoutError("Timeout"),
        ]
        
        for exc in exceptions:
            d = exc.to_dict()
            assert "type" in d
            assert "message" in d
            assert d["type"] == exc.__class__.__name__
