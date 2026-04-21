#!/usr/bin/env python3
"""
Centralized Logging Module for Garrison Engine.

Provides production-quality logging with configurable output formats,
levels, and optional file logging. Supports both text and JSON output
formats with optional colored console output.

Example:
    >>> from logger import get_logger
    >>> logger = get_logger(__name__)
    >>> logger.info("Scan started")
    >>> logger.warning("Pattern match in comment skipped")
"""

import os
import sys
import json
import threading
import logging
from typing import Optional, Dict, Any, Union
from datetime import datetime

# Optional colorama import for colored console output
try:
    from colorama import init as colorama_init, Fore, Style
    COLORAMA_AVAILABLE = True
    colorama_init(autoreset=True)
except ImportError:
    COLORAMA_AVAILABLE = False
    Fore = Style = None


# Default configuration
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "text"
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Color mapping for console output
COLOR_MAP = {
    "DEBUG": "CYAN",
    "INFO": "GREEN",
    "WARNING": "YELLOW",
    "ERROR": "RED",
    "CRITICAL": "MAGENTA",
}

# ANSI color codes (fallback if colorama not available)
ANSI_COLORS = {
    "RESET": "\033[0m",
    "CYAN": "\033[36m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "RED": "\033[31m",
    "MAGENTA": "\033[35m",
}


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to console output.
    
    Attributes:
        use_color: Whether to use colored output.
    """
    
    def __init__(self, fmt: Optional[str] = None, use_color: bool = True):
        """Initialize the formatter.
        
        Args:
            fmt: Format string for log messages.
            use_color: Whether to apply colors to output.
        """
        super().__init__(fmt)
        self.use_color = use_color and (COLORAMA_AVAILABLE or os.name != "nt")
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with optional color.
        
        Args:
            record: The log record to format.
            
        Returns:
            Formatted log message string.
        """
        # Save original levelname
        original_levelname = record.levelname
        
        if self.use_color:
            color_name = COLOR_MAP.get(record.levelname, "RESET")
            
            if COLORAMA_AVAILABLE and Fore and Style:
                color_attr = getattr(Fore, color_name, "")
                reset_attr = Style.RESET_ALL
                formatted = f"{color_attr}{record.levelname}{reset_attr}"
                record.levelname = formatted
            else:
                color_code = ANSI_COLORS.get(color_name, ANSI_COLORS["RESET"])
                reset_code = ANSI_COLORS["RESET"]
                formatted = f"{color_code}{record.levelname}{reset_code}"
                record.levelname = formatted
        
        result = super().format(record)
        record.levelname = original_levelname
        return result


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging.
    
    Outputs log records as JSON lines for machine parsing.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON.
        
        Args:
            record: The log record to format.
            
        Returns:
            JSON string representation of the log record.
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, "extra"):
            log_data.update(record.extra)
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Text formatter for human-readable logging.
    
    Format: [2025-12-21 10:30:00] [WARNING] [heuristic_scanner] Message
    """
    
    def __init__(self, fmt: Optional[str] = None):
        """Initialize the formatter.
        
        Args:
            fmt: Custom format string. Uses default if not provided.
        """
        default_fmt = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        super().__init__(fmt or default_fmt, datefmt="%Y-%m-%d %H:%M:%S")


# Global flag to track if logging has been configured
_logging_configured = False
_root_handlers: list = []
_logging_lock = threading.Lock()


def setup_logging(
    level: Optional[Union[str, int]] = None,
    format: Optional[str] = None,
    log_file: Optional[str] = None,
    use_color: bool = True,
) -> None:
    """Configure global logging settings.
    
    This function sets up the root logger with the specified configuration.
    It should be called once at application startup.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) or None
            to use env var.
        format: Output format ("text" or "json") or None to use env var.
        log_file: Path to log file for file logging or None to use env var.
        use_color: Whether to use colored console output.
        
    Example:
        >>> setup_logging(
        ...     level="DEBUG", format="json", log_file="garrison.log"
        ... )
    """
    global _logging_configured, _root_handlers

    with _logging_lock:
        # Get configuration from environment variables or defaults
        if level is None:
            level = os.environ.get("GARRISON_LOG_LEVEL", DEFAULT_LOG_LEVEL)

        if format is None:
            format = os.environ.get("GARRISON_LOG_FORMAT", DEFAULT_LOG_FORMAT)

        if log_file is None:
            log_file = os.environ.get("GARRISON_LOG_FILE")

        # Convert level string to int if needed
        if isinstance(level, str):
            level = LOG_LEVELS.get(level.upper(), logging.INFO)

        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)

        # Remove existing handlers to avoid duplicates
        for handler in _root_handlers:
            root_logger.removeHandler(handler)
        _root_handlers = []

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        if format.lower() == "json":
            console_handler.setFormatter(JSONFormatter())
        else:
            console_handler.setFormatter(ColoredFormatter(use_color=use_color))

        root_logger.addHandler(console_handler)
        _root_handlers.append(console_handler)

        # File handler (optional)
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(level)

            # Use JSON for file logs if specified, otherwise plain text
            if format.lower() == "json":
                file_handler.setFormatter(JSONFormatter())
            else:
                file_handler.setFormatter(TextFormatter())

            root_logger.addHandler(file_handler)
            _root_handlers.append(file_handler)

        _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name.
    
    Creates a properly configured logger following Python best practices.
    Uses the __name__ convention for hierarchical loggers.
    
    Args:
        name: The name for the logger (typically __name__).
        
    Returns:
        A configured Logger instance.
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing started")
    """
    global _logging_configured
    
    # Auto-configure logging if not already done
    if not _logging_configured:
        setup_logging()
    
    logger = logging.getLogger(name)
    
    # Ensure the logger doesn't propagate to avoid duplicate messages
    # when root logger has handlers
    logger.propagate = True
    
    return logger


def get_log_level() -> str:
    """Get the current log level from environment or default.
    
    Returns:
        The current log level string.
    """
    return os.environ.get("GARRISON_LOG_LEVEL", DEFAULT_LOG_LEVEL)


def get_log_format() -> str:
    """Get the current log format from environment or default.
    
    Returns:
        The current log format ("text" or "json").
    """
    return os.environ.get("GARRISON_LOG_FORMAT", DEFAULT_LOG_FORMAT)


# Convenience function for quick logging setup
def configure(
    level: Optional[str] = None,
    format: Optional[str] = None,
    log_file: Optional[str] = None,
) -> None:
    """Alias for setup_logging for simpler imports.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        format: Output format ("text" or "json").
        log_file: Path to log file for file logging.
        
    Example:
        >>> from logger import configure
        >>> configure(level="DEBUG", format="text")
    """
    setup_logging(level=level, format=format, log_file=log_file)


if __name__ == "__main__":
    # Demo/test code
    configure(level="DEBUG", format="text")
    
    test_logger = get_logger("garrison.test")
    
    test_logger.debug("This is a debug message")
    test_logger.info("This is an info message")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")
    test_logger.critical("This is a critical message")
    
    print("\n--- JSON Format Demo ---\n")
    
    configure(level="DEBUG", format="json")
    
    test_logger2 = get_logger("garrison.test.json")
    test_logger2.info("JSON formatted log message")
    test_logger2.warning("Pattern match in comment skipped")
