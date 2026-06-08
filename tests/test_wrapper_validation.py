"""Tests for wrapper input validation."""

from __future__ import annotations

import pytest

from exceptions import CounterscarpValidationError
from fuzz_wrapper import run_foundry_fuzz


class TestFuzzWrapperValidation:
    def test_rejects_invalid_contract_name(self):
        with pytest.raises(CounterscarpValidationError):
            run_foundry_fuzz("../../BadContract")
