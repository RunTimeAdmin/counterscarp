"""Tests for webapp/api_auth.py."""

from __future__ import annotations

import pytest

from webapp.api_auth import load_api_keys, verify_api_key


@pytest.fixture(autouse=True)
def clear_api_keys(monkeypatch):
    monkeypatch.delenv("COUNTERSCARP_API_KEYS", raising=False)
    monkeypatch.delenv("COUNTERSCARP_API_KEY", raising=False)


class TestLoadApiKeys:
    def test_parses_labeled_keys(self, monkeypatch):
        monkeypatch.setenv(
            "COUNTERSCARP_API_KEYS",
            "agent-a:secret-one,agent-b:secret-two",
        )
        keys = load_api_keys()
        assert keys == {"agent-a": "secret-one", "agent-b": "secret-two"}

    def test_parses_bare_secret(self, monkeypatch):
        monkeypatch.setenv("COUNTERSCARP_API_KEY", "bare-secret")
        keys = load_api_keys()
        assert len(keys) == 1
        assert "bare-secret" in keys.values()

    def test_verify_valid_key(self, monkeypatch):
        monkeypatch.setenv("COUNTERSCARP_API_KEYS", "virtuals:cs_test_key_123")
        client = verify_api_key("cs_test_key_123")
        assert client is not None
        assert client.client_id == "virtuals"

    def test_verify_invalid_key(self, monkeypatch):
        monkeypatch.setenv("COUNTERSCARP_API_KEYS", "virtuals:cs_test_key_123")
        assert verify_api_key("wrong-key") is None
