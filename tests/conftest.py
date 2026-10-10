"""Test suite fixtures and common test utilities for apisec."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from apisec.config.settings import Settings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def custom_settings(temp_dir: Path) -> Settings:
    """Provide a custom Settings instance backed by temporary storage."""
    return Settings(base_data_dir=temp_dir, db_name="test_apisec.db")
