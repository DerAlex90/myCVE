import copy

import pytest
from fastapi.testclient import TestClient

from mycve.server.api import create_app
from mycve.server.config import Settings
from mycve.server.db import Base, make_engine, sessions


@pytest.fixture
def engine():
    value = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(value)
    yield value
    value.dispose()


@pytest.fixture
def session(engine):
    with sessions(engine)() as value:
        yield value


@pytest.fixture
def client(engine):
    settings = Settings(
        allow_unauthenticated=True, api_key="", task_mode="inline", demo_mode=False, _env_file=None
    )
    with TestClient(create_app(settings, engine)) as value:
        yield value


@pytest.fixture
def advisory():
    return copy.deepcopy(
        {
            "id": "GHSA-test-test-test",
            "aliases": ["CVE-2024-12345"],
            "summary": "Test advisory",
            "details": "A fictional test fixture",
            "modified": "2026-10-01T00:00:00Z",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "example-http"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.5.0"}]}
                    ],
                }
            ],
        }
    )
