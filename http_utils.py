#!/usr/bin/env python3
"""
HTTP Utilities for Sentinel Engine.

Provides reusable retry logic, rate limiting, and resilient HTTP request
wrappers for external API calls. Implements exponential backoff with jitter
and proper error classification.

Example:
    >>> from http_utils import resilient_get, RateLimiter
    >>> limiter = RateLimiter(requests_per_second=2)
    >>> response = resilient_get(
    ...     "https://api.example.com/data",
    ...     rate_limiter=limiter,
    ...     max_retries=3
    ... )
"""

import time
import random
import functools
from typing import Optional, Callable, Any
from dataclasses import dataclass, field

import requests
from requests.exceptions import (
    Timeout, ConnectionError, RequestException
)

from logger import get_logger
from exceptions import SentinelAPIError, SentinelTimeoutError

# Import config loader
try:
    from config_loader import load_config, SentinelConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None


def get_config() -> SentinelConfig:
    """Get or load the configuration."""
    global _config
    if _config is None:
        if CONFIG_AVAILABLE:
            try:
                _config = load_config()
            except Exception:
                _config = SentinelConfig()
        else:
            _config = SentinelConfig()
    return _config


def get_http_timeout() -> int:
    """Get HTTP default timeout from config or use default."""
    try:
        return get_config().http.default_timeout
    except Exception:
        return 30


def get_http_max_retries() -> int:
    """Get HTTP max retries from config or use default."""
    try:
        return get_config().http.max_retries
    except Exception:
        return 3


def get_http_base_delay() -> float:
    """Get HTTP base delay from config or use default."""
    try:
        return get_config().http.base_delay
    except Exception:
        return 1.0


def get_http_max_delay() -> float:
    """Get HTTP max delay from config or use default."""
    try:
        return get_config().http.max_delay
    except Exception:
        return 30.0


def get_http_backoff_factor() -> float:
    """Get HTTP backoff factor from config or use default."""
    try:
        return get_config().http.backoff_factor
    except Exception:
        return 2.0


# Default configuration for HTTP requests (fallback values)
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0
DEFAULT_MAX_DELAY = 30.0
DEFAULT_BACKOFF_FACTOR = 2.0


def calculate_backoff(
    attempt: int,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    jitter: bool = True,
) -> float:
    """Calculate exponential backoff delay with optional jitter.
    
    Args:
        attempt: The current retry attempt (0-indexed).
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap in seconds.
        backoff_factor: Multiplier for exponential growth.
        jitter: Whether to add random jitter (0-1 seconds).
        
    Returns:
        Delay in seconds to wait before next retry.
    """
    delay = base_delay * (backoff_factor ** attempt)
    delay = min(delay, max_delay)
    
    if jitter:
        # Add random jitter between 0 and 1 second
        delay += random.uniform(0, 1)
    
    return delay


def classify_http_error(status_code: int) -> str:
    """Classify HTTP status code for retry decision.
    
    Args:
        status_code: HTTP status code.
        
    Returns:
        Classification string: 'retry', 'retry_long', 'no_retry', or 'success'.
    """
    if 200 <= status_code < 300:
        return "success"
    elif status_code == 429:
        # Rate limited - retry with longer backoff
        return "retry_long"
    elif status_code >= 500:
        # Server errors - retry
        return "retry"
    elif status_code >= 400:
        # Client errors - don't retry (except 429 handled above)
        return "no_retry"
    else:
        # Other codes (redirects, etc.) - treat as retry
        return "retry"


def retry_request(
    func: Optional[Callable] = None,
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    exceptions_to_retry: tuple = (RequestException,),
) -> Callable:
    """Decorator that implements exponential backoff retry logic.
    
    Args:
        func: The function to wrap (automatically provided when used as
            decorator).
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay cap in seconds.
        backoff_factor: Exponential backoff multiplier.
        exceptions_to_retry: Tuple of exceptions that should trigger a retry.
        
    Returns:
        Decorated function with retry logic.
        
    Example:
        >>> @retry_request(max_retries=3)
        ... def fetch_data(url):
        ...     return requests.get(url)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions_to_retry as e:
                    last_exception = e
                    
                    if attempt >= max_retries:
                        logger.warning(
                            f"Max retries ({max_retries}) exceeded for "
                            f"{func.__name__}"
                        )
                        raise
                    
                    # Calculate delay with exponential backoff
                    delay = calculate_backoff(
                        attempt=attempt,
                        base_delay=base_delay,
                        max_delay=max_delay,
                        backoff_factor=backoff_factor,
                    )
                    
                    logger.info(
                        f"Retry {attempt + 1}/{max_retries} for "
                        f"{func.__name__} after {delay:.2f}s delay: {e}"
                    )
                    time.sleep(delay)
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
            
        return wrapper
    
    # Support both @retry_request and @retry_request() syntax
    if func is not None:
        return decorator(func)
    return decorator


@dataclass
class RateLimiter:
    """Token bucket rate limiter for controlling request rates.
    
    Implements a simple token bucket algorithm to limit the rate of
    requests per second or per minute.
    
    Attributes:
        requests_per_second: Maximum requests allowed per second.
        requests_per_minute: Alternative limit for requests per minute.
        
    Example:
        >>> limiter = RateLimiter(requests_per_second=2)
        >>> limiter.acquire()  # Blocks if rate exceeded
        >>> # Make request
        >>> limiter.release()  # Not needed for simple token bucket
    """
    requests_per_second: Optional[float] = None
    requests_per_minute: Optional[float] = None
    _tokens: float = field(default=0, repr=False)
    _last_update: float = field(default_factory=time.time, repr=False)
    _max_tokens: float = field(default=0, repr=False)
    _token_rate: float = field(default=0, repr=False)
    
    def __post_init__(self):
        """Initialize rate limiter parameters."""
        if self.requests_per_second is not None:
            self._token_rate = self.requests_per_second
            self._max_tokens = max(1, self.requests_per_second)
        elif self.requests_per_minute is not None:
            self._token_rate = self.requests_per_minute / 60.0
            self._max_tokens = max(1, self.requests_per_minute / 60.0)
        else:
            # Default: 10 requests per second
            self._token_rate = 10.0
            self._max_tokens = 10.0
        
        self._tokens = self._max_tokens
    
    def acquire(self, tokens: float = 1.0) -> None:
        """Acquire tokens from the bucket, blocking if necessary.
        
        Args:
            tokens: Number of tokens to acquire (default 1 for one request).
        """
        self._add_tokens()
        
        if self._tokens < tokens:
            # Calculate wait time needed
            deficit = tokens - self._tokens
            wait_time = deficit / self._token_rate
            logger.debug(f"Rate limiter waiting {wait_time:.2f}s")
            time.sleep(wait_time)
            self._add_tokens()
        
        self._tokens -= tokens
    
    def _add_tokens(self) -> None:
        """Add tokens to the bucket based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_update
        self._last_update = now
        
        self._tokens = min(
            self._max_tokens, self._tokens + elapsed * self._token_rate
        )


def resilient_request(
    method: str,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    rate_limiter: Optional[RateLimiter] = None,
    **kwargs
) -> requests.Response:
    """Make an HTTP request with retry logic, rate limiting, and proper error
    handling.
    
    Args:
        method: HTTP method ('GET', 'POST', etc.).
        url: The URL to request.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
        rate_limiter: Optional RateLimiter instance to control request rate.
        **kwargs: Additional arguments passed to requests.request().
        
    Returns:
        Response object from successful request.
        
    Raises:
        SentinelTimeoutError: If the request times out.
        SentinelAPIError: If the request fails after all retries or returns
            4xx error.
        
    Example:
        >>> response = resilient_request('GET', 'https://api.example.com/data')
        >>> data = response.json()
    """
    if rate_limiter:
        rate_limiter.acquire()
    
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            logger.debug(
                f"{method} {url} (attempt {attempt + 1}/{max_retries + 1})"
            )
            
            response = requests.request(
                method=method,
                url=url,
                timeout=timeout,
                **kwargs
            )
            
            # Check status code classification
            classification = classify_http_error(response.status_code)
            
            if classification == "success":
                return response
            
            elif classification == "no_retry":
                # 4xx errors (except 429) - don't retry
                raise SentinelAPIError(
                    f"HTTP {response.status_code} error from {url}",
                    details={
                        "url": url,
                        "method": method,
                        "status_code": response.status_code,
                        "response_text": response.text[:500] if response.text else None,
                    }
                )
            
            elif classification == "retry_long":
                # 429 rate limited - use longer backoff
                if attempt < max_retries:
                    # Check for Retry-After header
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except ValueError:
                            delay = calculate_backoff(attempt, base_delay=5.0)
                    else:
                        delay = calculate_backoff(attempt, base_delay=5.0)
                    
                    logger.warning(
                        f"Rate limited (429) on {url}, waiting "
                        f"{delay:.2f}s before retry"
                    )
                    time.sleep(delay)
                    continue
                else:
                    raise SentinelAPIError(
                        f"Rate limited (429) after {max_retries} "
                        f"retries: {url}",
                        details={
                            "url": url,
                            "method": method,
                            "status_code": 429,
                        }
                    )
            
            elif classification == "retry":
                # 5xx errors - retry with exponential backoff
                if attempt < max_retries:
                    delay = calculate_backoff(attempt)
                    logger.warning(
                        f"Server error ({response.status_code}) on {url}, "
                        f"retrying in {delay:.2f}s "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(delay)
                    continue
                else:
                    raise SentinelAPIError(
                        f"Server error ({response.status_code}) after "
                        f"{max_retries} retries: {url}",
                        details={
                            "url": url,
                            "method": method,
                            "status_code": response.status_code,
                            "response_text": (
                                response.text[:500] if response.text else None
                            ),
                        }
                    )
        
        except Timeout as e:
            last_exception = e
            if attempt < max_retries:
                delay = calculate_backoff(attempt)
                logger.warning(
                    f"Timeout on {url}, retrying in {delay:.2f}s "
                    f"(attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
            else:
                raise SentinelTimeoutError(
                    f"Request timed out after {max_retries + 1} "
                    f"attempts: {url}",
                    details={
                        "url": url,
                        "method": method,
                        "timeout_seconds": timeout,
                        "attempts": max_retries + 1,
                    }
                ) from e
        
        except ConnectionError as e:
            last_exception = e
            if attempt < max_retries:
                delay = calculate_backoff(attempt)
                logger.warning(
                    f"Connection error on {url}, retrying in {delay:.2f}s "
                    f"(attempt {attempt + 1}/{max_retries}): {e}"
                )
                time.sleep(delay)
            else:
                raise SentinelAPIError(
                    f"Connection failed after {max_retries + 1} "
                    f"attempts: {url}",
                    details={
                        "url": url,
                        "method": method,
                        "error_type": "connection_error",
                    }
                ) from e
        
        except RequestException as e:
            last_exception = e
            if attempt < max_retries:
                delay = calculate_backoff(attempt)
                logger.warning(
                    f"Request error on {url}, retrying in {delay:.2f}s "
                    f"(attempt {attempt + 1}/{max_retries}): {e}"
                )
                time.sleep(delay)
            else:
                raise SentinelAPIError(
                    f"Request failed after {max_retries + 1} attempts: {url}",
                    details={
                        "url": url,
                        "method": method,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                ) from e
    
    # Should not reach here, but handle just in case
    if last_exception:
        raise SentinelAPIError(
            f"Unexpected error in resilient_request: {url}",
            details={
                "url": url,
                "method": method,
                "error": str(last_exception),
            }
        ) from last_exception
    
    raise SentinelAPIError(
        f"Unknown error in resilient_request: {url}",
        details={"url": url, "method": method}
    )


def resilient_get(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    rate_limiter: Optional[RateLimiter] = None,
    **kwargs
) -> requests.Response:
    """Make a resilient GET request with retry logic and rate limiting.
    
    Args:
        url: The URL to request.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
        rate_limiter: Optional RateLimiter instance.
        **kwargs: Additional arguments passed to requests.get().
        
    Returns:
        Response object from successful request.
        
    Raises:
        SentinelTimeoutError: If the request times out.
        SentinelAPIError: If the request fails after all retries.
        
    Example:
        >>> response = resilient_get('https://api.example.com/data')
        >>> data = response.json()
    """
    return resilient_request(
        method='GET',
        url=url,
        timeout=timeout,
        max_retries=max_retries,
        rate_limiter=rate_limiter,
        **kwargs
    )


def resilient_post(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    rate_limiter: Optional[RateLimiter] = None,
    **kwargs
) -> requests.Response:
    """Make a resilient POST request with retry logic and rate limiting.
    
    Args:
        url: The URL to request.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
        rate_limiter: Optional RateLimiter instance.
        **kwargs: Additional arguments passed to requests.post().
        
    Returns:
        Response object from successful request.
        
    Raises:
        SentinelTimeoutError: If the request times out.
        SentinelAPIError: If the request fails after all retries.
        
    Example:
        >>> response = resilient_post(
        ...     'https://api.example.com/data',
        ...     json={'key': 'value'}
        ... )
    """
    return resilient_request(
        method='POST',
        url=url,
        timeout=timeout,
        max_retries=max_retries,
        rate_limiter=rate_limiter,
        **kwargs
    )


if __name__ == "__main__":
    # Demo/test code
    import sys
    
    print("Testing HTTP Utilities\n")
    
    # Test rate limiter
    print("1. Testing RateLimiter:")
    limiter = RateLimiter(requests_per_second=2)
    start = time.time()
    for i in range(5):
        limiter.acquire()
        print(f"   Request {i + 1} at {time.time() - start:.2f}s")
    elapsed = time.time() - start
    print(f"   Total time: {elapsed:.2f}s (expected ~2s for 5req at 2/sec)\n")
    
    # Test backoff calculation
    print("2. Testing backoff calculation:")
    for i in range(5):
        delay = calculate_backoff(i, base_delay=1.0, max_delay=30.0)
        print(f"   Attempt {i}: {delay:.2f}s delay")
    print()
    
    # Test HTTP error classification
    print("3. Testing HTTP error classification:")
    test_codes = [200, 404, 429, 500, 503]
    for code in test_codes:
        classification = classify_http_error(code)
        print(f"   HTTP {code}: {classification}")
    print()
    
    # Test resilient request (if URL provided)
    if len(sys.argv) > 1:
        test_url = sys.argv[1]
        print(f"4. Testing resilient_get to {test_url}:")
        try:
            response = resilient_get(test_url, max_retries=2)
            print(f"   Success: HTTP {response.status_code}")
            print(f"   Content length: {len(response.text)} bytes")
        except SentinelAPIError as e:
            print(f"   API Error: {e}")
        except SentinelTimeoutError as e:
            print(f"   Timeout Error: {e}")
    else:
        print("4. Skipping resilient request test (provide URL as argument)")
