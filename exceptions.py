#!/usr/bin/env python3
"""
Custom Exception Hierarchy for Sentinel Engine.

Provides a clean, structured exception hierarchy for all Sentinel Engine
errors. Each exception supports optional details dict for structured error
context and preserves original exception chaining.

Example:
    >>> from exceptions import SentinelConfigError
    >>> try:
    ...     load_config("invalid.toml")
    ... except Exception as e:
    ...     raise SentinelConfigError(
    ...         "Failed to load config", details={"path": "invalid.toml"}
    ...     ) from e
"""

from typing import Optional, Dict, Any


class SentinelError(Exception):
    """Base exception for all Sentinel Engine errors.
    
    All custom exceptions in the Sentinel Engine should inherit from this
    class to allow for unified error handling.
    
    Attributes:
        message: The error message.
        details: Optional dictionary containing structured error context.
    
    Example:
        >>> raise SentinelError("Generic error occurred")
        >>> raise SentinelError("Generic error", details={"code": 500})
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the exception.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with structured error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        """Return string representation of the error.
        
        Returns:
            Formatted error message including details if present.
        """
        if self.details:
            details_str = ", ".join(
                f"{k}={repr(v)}" for k, v in self.details.items()
            )
            return f"{self.message} ({details_str})"
        return self.message
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for serialization.
        
        Returns:
            Dictionary containing error information.
        """
        result: Dict[str, Any] = {
            "type": self.__class__.__name__,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        if self.__cause__:
            result["cause"] = str(self.__cause__)
        return result


class SentinelConfigError(SentinelError):
    """Raised for configuration loading/validation errors.
    
    This exception is raised when there's a problem with loading or
    validating the Sentinel configuration file (sentinel.toml).
    
    Example:
        >>> raise SentinelConfigError(
        ...     "Invalid TOML syntax",
        ...     details={"path": "/path/to/config.toml", "line": 42}
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the config error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'path', 'line'.
        """
        super().__init__(message, details)


class SentinelAnalysisError(SentinelError):
    """Raised when a security analyzer fails.
    
    This exception is raised when static analysis, fuzzing, or other
    security analysis tools fail to execute properly.
    
    Example:
        >>> raise SentinelAnalysisError(
        ...     "Slither analysis failed",
        ...     details={"tool": "slither", "contract": "Token.sol"}
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the analysis error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'tool', 'contract'.
        """
        super().__init__(message, details)


class SentinelAPIError(SentinelError):
    """Raised for external API call failures.
    
    This exception is raised when external API calls fail, such as
    threat intelligence lookups, OSV database queries, or other
    external service interactions.
    
    Example:
        >>> raise SentinelAPIError(
        ...     "OSV API request failed",
        ...     details={
        ...         "api": "osv", "status_code": 503, "endpoint": "/v1/query"
        ...     }
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the API error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'api',
                'status_code'.
        """
        super().__init__(message, details)


class SentinelReportError(SentinelError):
    """Raised for report generation failures.
    
    This exception is raised when the report generator fails to create
    output files or format findings properly.
    
    Example:
        >>> raise SentinelReportError(
        ...     "Failed to write HTML report",
        ...     details={"format": "html", "output_path": "/reports/out.html"}
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the report error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'format',
                'output_path'.
        """
        super().__init__(message, details)


class SentinelToolNotFoundError(SentinelError):
    """Raised when a required external tool is not found.
    
    This exception is raised when external tools like Slither, Aderyn,
    Medusa, or Mythril are not installed or not available in PATH.
    
    Example:
        >>> raise SentinelToolNotFoundError(
        ...     "Slither not found in PATH",
        ...     details={
        ...         "tool": "slither",
        ...         "install_cmd": "pip install slither-analyzer"
        ...     }
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the tool not found error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'tool',
                'install_cmd'.
        """
        super().__init__(message, details)


class SentinelValidationError(SentinelError):
    """Raised for input validation failures.
    
    This exception is raised when user input or scanned code fails
    validation checks.
    
    Example:
        >>> raise SentinelValidationError(
        ...     "Invalid contract address format",
        ...     details={"field": "address", "value": "0x123"}
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the validation error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'field', 'value'.
        """
        super().__init__(message, details)


class SentinelTimeoutError(SentinelError):
    """Raised when an operation times out.
    
    This exception is raised when analysis operations exceed their
    configured timeout limits.
    
    Example:
        >>> raise SentinelTimeoutError(
        ...     "Mythril analysis timed out",
        ...     details={
        ...         "operation": "symbolic_analysis", "timeout_seconds": 300
        ...     }
        ... )
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the timeout error.
        
        Args:
            message: Human-readable error message.
            details: Optional dictionary with context like 'operation',
                'timeout_seconds'.
        """
        super().__init__(message, details)


# Module-level convenience functions
def format_exception_chain(exc: Exception) -> str:
    """Format an exception and its cause chain for display.
    
    Args:
        exc: The exception to format.
        
    Returns:
        Formatted string showing the exception chain.
        
    Example:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     print(format_exception_chain(e))
    """
    lines = [str(exc)]
    current = exc.__cause__
    
    while current:
        lines.append(f"  Caused by: {current}")
        current = current.__cause__
    
    return "\n".join(lines)


def is_sentinel_error(exc: Exception) -> bool:
    """Check if an exception is a Sentinel Engine error.
    
    Args:
        exc: The exception to check.
        
    Returns:
        True if the exception is a SentinelError or subclass.
    """
    return isinstance(exc, SentinelError)


if __name__ == "__main__":
    # Demo/test code
    print("Testing Sentinel Exception Hierarchy\n")
    
    # Test basic exception
    try:
        raise SentinelError("Generic error", details={"code": 500})
    except SentinelError as e:
        print(f"1. Basic error: {e}")
        print(f"   Dict: {e.to_dict()}\n")
    
    # Test exception chaining
    try:
        try:
            raise ValueError("Original error")
        except ValueError as original:
            raise SentinelConfigError(
                "Config load failed",
                details={"path": "config.toml"}
            ) from original
    except SentinelError as e:
        print(f"2. Chained error: {e}")
        print(f"   Cause: {e.__cause__}")
        print(f"   Formatted chain:\n   {format_exception_chain(e)}\n")
    
    # Test all exception types
    exceptions_to_test = [
        SentinelConfigError("Config error", {"file": "test.toml"}),
        SentinelAnalysisError("Analysis failed", {"tool": "slither"}),
        SentinelAPIError("API error", {"status": 500}),
        SentinelReportError("Report failed", {"format": "html"}),
        SentinelToolNotFoundError("Tool missing", {"tool": "mythril"}),
        SentinelValidationError("Invalid input", {"field": "address"}),
        SentinelTimeoutError("Timeout", {"seconds": 30}),
    ]
    
    print("3. All exception types:")
    for exc in exceptions_to_test:
        print(f"   - {exc.__class__.__name__}: {exc}")
    
    print("\n4. Exception hierarchy check:")
    print(f"   SentinelConfigError is SentinelError: "
          f"{is_sentinel_error(SentinelConfigError('test'))}")
    print(f"   ValueError is SentinelError: "
          f"{is_sentinel_error(ValueError('test'))}")
