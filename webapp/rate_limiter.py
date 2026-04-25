"""Sliding-window rate limiter with Redis backend and in-memory fallback.

The lightweight ``RateLimiter`` class requires only Python stdlib.
``RedisRateLimiter`` adds a Redis-backed sliding window and falls back to
``RateLimiter`` automatically when Redis is unavailable or not configured.
"""

import os
import time
from collections import defaultdict
from threading import Lock
from typing import Optional


_TRUSTED_PROXIES: set[str] = set(
    p.strip() for p in os.environ.get("TRUSTED_PROXIES", "127.0.0.1").split(",") if p.strip()
)


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


class RedisRateLimiter:
    """Redis-backed sliding window rate limiter with in-memory fallback.

    Falls back to thread-safe in-memory limiter when Redis is unavailable.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        redis_url: Optional[str] = None,
        prefix: str = "rl",
    ) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._prefix = prefix
        self._fallback = RateLimiter(max_requests, window_seconds)
        self._redis = None
        if redis_url:
            try:
                import redis as redis_lib
                self._redis = redis_lib.from_url(
                    redis_url, decode_responses=True, socket_timeout=2
                )
                self._redis.ping()  # verify connection
            except Exception:
                self._redis = None  # fall back to in-memory

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed under rate limit."""
        if self._redis is None:
            return self._fallback.is_allowed(key)

        redis_key = f"{self._prefix}:{key}"
        now = time.time()
        window_start = now - self.window

        try:
            pipe = self._redis.pipeline(True)
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zadd(redis_key, {str(now): now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, self.window + 1)
            results = pipe.execute()
            count = results[2]
            return bool(count <= self.max_requests)
        except Exception:
            # Redis failure — fall back to in-memory
            return self._fallback.is_allowed(key)

    def remaining(self, key: str) -> int:
        """Return remaining requests in current window."""
        if self._redis is None:
            # approximate from fallback
            return max(0, self.max_requests - len(self._fallback._requests.get(key, [])))

        redis_key = f"{self._prefix}:{key}"
        now = time.time()
        window_start = now - self.window

        try:
            pipe = self._redis.pipeline(True)
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zcard(redis_key)
            results = pipe.execute()
            count = results[1]
            return int(max(0, self.max_requests - count))
        except Exception:
            return self.max_requests  # assume allowed on error


def get_client_ip(request) -> str:
    """Extract client IP, only trusting X-Forwarded-For from trusted proxies."""
    peer: str = request.client.host if request.client else "unknown"
    if peer in _TRUSTED_PROXIES:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return str(forwarded.split(",")[0].strip())
    return peer
