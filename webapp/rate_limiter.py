"""Lightweight in-memory sliding-window rate limiter.

No external dependencies — uses only Python stdlib.
"""

import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Args:
        max_requests: Maximum number of requests allowed within *window_seconds*.
        window_seconds: Duration of the sliding window in seconds.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """Check whether *key* (e.g. an IP address) is within the rate limit.

        Returns True and records the request if allowed; returns False if the
        limit has been reached for the current window.
        """
        now = time.time()
        with self._lock:
            # Evict timestamps that have fallen outside the window
            self._requests[key] = [
                t for t in self._requests[key] if now - t < self.window
            ]
            if len(self._requests[key]) >= self.max_requests:
                return False
            self._requests[key].append(now)
            return True
