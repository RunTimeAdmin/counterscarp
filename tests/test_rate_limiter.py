"""Tests for webapp/rate_limiter.py — RateLimiter class."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from webapp.rate_limiter import RateLimiter


class TestRateLimiterBasic:
    def test_first_request_allowed(self) -> None:
        rl = RateLimiter(max_requests=5, window_seconds=60)
        assert rl.is_allowed("ip1") is True

    def test_requests_within_limit_allowed(self) -> None:
        rl = RateLimiter(max_requests=3, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True

    def test_request_at_limit_blocked(self) -> None:
        rl = RateLimiter(max_requests=3, window_seconds=60)
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip1") is False

    def test_different_keys_independent(self) -> None:
        rl = RateLimiter(max_requests=1, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip2") is True
        # ip1 is now exhausted
        assert rl.is_allowed("ip1") is False
        # ip2 is also exhausted
        assert rl.is_allowed("ip2") is False

    def test_max_requests_one(self) -> None:
        rl = RateLimiter(max_requests=1, window_seconds=60)
        assert rl.is_allowed("key") is True
        assert rl.is_allowed("key") is False

    def test_window_expiry_clears_old_requests(self) -> None:
        """Old timestamps outside the window should be evicted."""
        rl = RateLimiter(max_requests=2, window_seconds=1)
        rl.is_allowed("ip")
        rl.is_allowed("ip")
        # Both slots used — blocked
        assert rl.is_allowed("ip") is False
        # Wait for window to expire
        time.sleep(1.1)
        # Old requests should be evicted; new request allowed
        assert rl.is_allowed("ip") is True

    def test_zero_max_requests_always_blocked(self) -> None:
        rl = RateLimiter(max_requests=0, window_seconds=60)
        assert rl.is_allowed("ip") is False

    def test_large_window_keeps_history(self) -> None:
        rl = RateLimiter(max_requests=100, window_seconds=3600)
        for i in range(100):
            assert rl.is_allowed("ip") is True
        assert rl.is_allowed("ip") is False

    def test_multiple_keys_do_not_interfere(self) -> None:
        rl = RateLimiter(max_requests=2, window_seconds=60)
        for key in ("a", "b", "c"):
            assert rl.is_allowed(key) is True
            assert rl.is_allowed(key) is True
            assert rl.is_allowed(key) is False

    def test_mock_time_window_sliding(self) -> None:
        """Use mock time to verify sliding-window eviction without sleeping."""
        rl = RateLimiter(max_requests=2, window_seconds=10)
        base = 1000.0
        with patch("webapp.rate_limiter.time") as mock_time:
            mock_time.time.return_value = base
            rl.is_allowed("ip")  # t=1000
            mock_time.time.return_value = base + 5
            rl.is_allowed("ip")  # t=1005 (limit reached)
            mock_time.time.return_value = base + 5
            assert rl.is_allowed("ip") is False

            # Advance past first request's expiry
            mock_time.time.return_value = base + 11  # t=1000 falls out of [1001, 1011)
            assert rl.is_allowed("ip") is True  # t=1005 still in window, slot freed


class TestRateLimiterThreadSafety:
    def test_concurrent_requests_respect_limit(self) -> None:
        """Concurrent requests must not exceed the max_requests limit."""
        import threading

        rl = RateLimiter(max_requests=5, window_seconds=60)
        results: list[bool] = []
        lock = threading.Lock()

        def make_request() -> None:
            result = rl.is_allowed("shared_ip")
            with lock:
                results.append(result)

        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        blocked = sum(1 for r in results if not r)
        assert allowed == 5
        assert blocked == 5
