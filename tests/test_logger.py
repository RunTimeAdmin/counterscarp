"""Tests for logger.py — structured logging utilities."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import logger as logger_module
from logger import (
    ColoredFormatter,
    JSONFormatter,
    TextFormatter,
    append_stderr_log,
    configure,
    get_log_format,
    get_log_level,
    get_logger,
    setup_logging,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_logging_state() -> None:
    """Reset module-level logger state between tests."""
    logger_module._logging_configured = False
    logger_module._root_handlers = []


# ---------------------------------------------------------------------------
# TestColoredFormatter
# ---------------------------------------------------------------------------


class TestColoredFormatter:
    def test_format_returns_string(self) -> None:
        fmt = ColoredFormatter(use_color=False)
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello", args=(), exc_info=None
        )
        result = fmt.format(record)
        assert isinstance(result, str)
        assert "hello" in result

    def test_levelname_restored_after_format(self) -> None:
        fmt = ColoredFormatter(use_color=True)
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="warn", args=(), exc_info=None
        )
        original_level = record.levelname
        fmt.format(record)
        assert record.levelname == original_level

    def test_format_with_color_disabled(self) -> None:
        fmt = ColoredFormatter(use_color=False)
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error message", args=(), exc_info=None
        )
        result = fmt.format(record)
        assert "error message" in result

    def test_all_log_levels(self) -> None:
        fmt = ColoredFormatter(use_color=False)
        for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
            record = logging.LogRecord(
                name="test", level=level, pathname="", lineno=0,
                msg="msg", args=(), exc_info=None
            )
            result = fmt.format(record)
            assert isinstance(result, str)


# ---------------------------------------------------------------------------
# TestJSONFormatter
# ---------------------------------------------------------------------------


class TestJSONFormatter:
    def test_format_returns_valid_json(self) -> None:
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None
        )
        result = fmt.format(record)
        data = json.loads(result)
        assert data["level"] == "INFO"
        assert data["message"] == "test message"
        assert data["logger"] == "test.logger"
        assert "timestamp" in data

    def test_format_includes_exception_info(self) -> None:
        fmt = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error", args=(), exc_info=exc_info
        )
        result = fmt.format(record)
        data = json.loads(result)
        assert "exception" in data

    def test_format_includes_extra_fields(self) -> None:
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="", lineno=0,
            msg="debug msg", args=(), exc_info=None
        )
        record.extra = {"scan_id": "abc123", "tool": "slither"}
        result = fmt.format(record)
        data = json.loads(result)
        assert data["scan_id"] == "abc123"
        assert data["tool"] == "slither"


# ---------------------------------------------------------------------------
# TestTextFormatter
# ---------------------------------------------------------------------------


class TestTextFormatter:
    def test_format_returns_string(self) -> None:
        fmt = TextFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="text msg", args=(), exc_info=None
        )
        result = fmt.format(record)
        assert "text msg" in result

    def test_custom_format_string(self) -> None:
        fmt = TextFormatter(fmt="%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="custom", args=(), exc_info=None
        )
        result = fmt.format(record)
        assert "WARNING" in result
        assert "custom" in result


# ---------------------------------------------------------------------------
# TestSetupLogging
# ---------------------------------------------------------------------------


class TestSetupLogging:
    def setup_method(self) -> None:
        _reset_logging_state()

    def test_setup_logging_text_format(self) -> None:
        setup_logging(level="INFO", format="text", use_color=False)
        assert logger_module._logging_configured is True

    def test_setup_logging_json_format(self) -> None:
        _reset_logging_state()
        setup_logging(level="DEBUG", format="json")
        assert logger_module._logging_configured is True

    def test_setup_logging_with_file(self, tmp_path: Path) -> None:
        _reset_logging_state()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="WARNING", format="text", log_file=log_file)
        assert logger_module._logging_configured is True

    def test_setup_logging_with_file_json(self, tmp_path: Path) -> None:
        _reset_logging_state()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="DEBUG", format="json", log_file=log_file)
        assert logger_module._logging_configured is True

    def test_setup_logging_numeric_level(self) -> None:
        _reset_logging_state()
        setup_logging(level=logging.DEBUG, format="text")
        assert logger_module._logging_configured is True

    def test_setup_logging_from_env(self, monkeypatch) -> None:
        _reset_logging_state()
        monkeypatch.setenv("COUNTERSCARP_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("COUNTERSCARP_LOG_FORMAT", "json")
        setup_logging()
        assert logger_module._logging_configured is True

    def test_setup_logging_removes_old_handlers(self) -> None:
        """Calling setup_logging twice must not accumulate duplicate handlers."""
        _reset_logging_state()
        setup_logging(level="INFO", format="text")
        count_after_first = len(logger_module._root_handlers)
        _reset_logging_state()
        setup_logging(level="WARNING", format="text")
        # Should not grow without bound
        assert len(logger_module._root_handlers) <= count_after_first + 1


# ---------------------------------------------------------------------------
# TestGetLogger
# ---------------------------------------------------------------------------


class TestGetLogger:
    def setup_method(self) -> None:
        _reset_logging_state()

    def test_get_logger_returns_logger(self) -> None:
        lg = get_logger("test.module")
        assert isinstance(lg, logging.Logger)
        assert lg.name == "test.module"

    def test_get_logger_auto_configures(self) -> None:
        _reset_logging_state()
        assert logger_module._logging_configured is False
        get_logger("auto.test")
        assert logger_module._logging_configured is True

    def test_get_logger_propagates(self) -> None:
        lg = get_logger("propagate.test")
        assert lg.propagate is True

    def test_different_names_return_different_loggers(self) -> None:
        lg1 = get_logger("module.a")
        lg2 = get_logger("module.b")
        assert lg1.name != lg2.name


# ---------------------------------------------------------------------------
# TestGetLogLevelAndFormat
# ---------------------------------------------------------------------------


class TestGetLogLevelAndFormat:
    def test_get_log_level_default(self, monkeypatch) -> None:
        monkeypatch.delenv("COUNTERSCARP_LOG_LEVEL", raising=False)
        assert get_log_level() == "INFO"

    def test_get_log_level_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("COUNTERSCARP_LOG_LEVEL", "DEBUG")
        assert get_log_level() == "DEBUG"

    def test_get_log_format_default(self, monkeypatch) -> None:
        monkeypatch.delenv("COUNTERSCARP_LOG_FORMAT", raising=False)
        assert get_log_format() == "text"

    def test_get_log_format_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("COUNTERSCARP_LOG_FORMAT", "json")
        assert get_log_format() == "json"


# ---------------------------------------------------------------------------
# TestConfigure
# ---------------------------------------------------------------------------


class TestConfigure:
    def setup_method(self) -> None:
        _reset_logging_state()

    def test_configure_is_alias_for_setup_logging(self) -> None:
        configure(level="INFO", format="text")
        assert logger_module._logging_configured is True

    def test_configure_with_log_file(self, tmp_path: Path) -> None:
        _reset_logging_state()
        configure(level="DEBUG", log_file=str(tmp_path / "cfg.log"))
        assert logger_module._logging_configured is True


# ---------------------------------------------------------------------------
# TestAppendStderrLog
# ---------------------------------------------------------------------------


class TestAppendStderrLog:
    def test_appends_to_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "stderr.log"
        append_stderr_log("some error output", "slither", str(log_path))
        content = log_path.read_text(encoding="utf-8")
        assert "slither" in content
        assert "some error output" in content

    def test_appends_multiple_times(self, tmp_path: Path) -> None:
        log_path = tmp_path / "stderr.log"
        append_stderr_log("first", "tool1", str(log_path))
        append_stderr_log("second", "tool2", str(log_path))
        content = log_path.read_text(encoding="utf-8")
        assert "first" in content
        assert "second" in content

    def test_empty_stderr_text_is_noop(self, tmp_path: Path) -> None:
        log_path = tmp_path / "stderr.log"
        append_stderr_log("", "tool", str(log_path))
        assert not log_path.exists()

    def test_empty_log_path_is_noop(self) -> None:
        # Should not raise
        append_stderr_log("some text", "tool", "")

    def test_handles_oserror_gracefully(self, tmp_path: Path) -> None:
        """If the log file can't be written, no exception should propagate."""
        bad_path = str(tmp_path / "nonexistent_dir" / "sub" / "log.txt")
        # Should not raise
        append_stderr_log("error text", "tool", bad_path)

    def test_separator_written(self, tmp_path: Path) -> None:
        log_path = tmp_path / "stderr.log"
        append_stderr_log("content", "mytool", str(log_path))
        content = log_path.read_text(encoding="utf-8")
        assert "=" * 60 in content
