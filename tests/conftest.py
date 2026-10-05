from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cra_toolkit.i18n import set_language

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _german_by_default() -> Iterator[None]:
    """Output language is process-global; reset it around every test."""
    set_language("de")
    yield
    set_language("de")


@pytest.fixture
def sample_project() -> Path:
    return FIXTURES / "sample-project"


@pytest.fixture
def osv_db() -> Path:
    return FIXTURES / "osv-db"
