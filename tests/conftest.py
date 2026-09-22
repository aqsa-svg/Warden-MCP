"""Shared pytest configuration."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Run @pytest.mark.anyio tests on asyncio only -- trio is not a dependency."""
    return "asyncio"
