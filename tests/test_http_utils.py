"""Tests for SSRF hardening in http_utils."""

from __future__ import annotations

import pytest

from exceptions import CounterscarpAPIError
from http_utils import _validate_outbound_url


def test_validate_outbound_url_allows_https_public_domain() -> None:
    _validate_outbound_url("https://example.com/api")


def test_validate_outbound_url_blocks_non_http_scheme() -> None:
    with pytest.raises(CounterscarpAPIError):
        _validate_outbound_url("file:///etc/passwd")


def test_validate_outbound_url_blocks_loopback() -> None:
    with pytest.raises(CounterscarpAPIError):
        _validate_outbound_url("http://127.0.0.1/admin")


def test_validate_outbound_url_blocks_private_ip() -> None:
    with pytest.raises(CounterscarpAPIError):
        _validate_outbound_url("http://10.0.0.5/internal")
