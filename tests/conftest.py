"""Shared pytest fixtures (~ spec/rails_helper.rb)."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from threatfeed.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    # The `with` block runs the app lifespan (startup / shutdown) around each test.
    with TestClient(app) as c:
        yield c
