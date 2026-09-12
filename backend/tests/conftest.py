import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["DATABASE_URL"] = "sqlite:///./test_chekwe.db"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["DEMO_MODE"] = "true"

from app.main import app          # noqa: E402
from app.database import Base, engine  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    from app.seed import run_seed
    run_seed()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def login(client, username, password):
    r = client.post("/api/v1/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin(client):
    return login(client, "admin", "admin123!")


@pytest.fixture
def analyst(client):
    return login(client, "analyst", "analyst123!")


@pytest.fixture
def viewer(client):
    return login(client, "viewer", "viewer123!")


def ingest(client, auth, **kwargs):
    return client.post("/api/v1/events", json=kwargs, headers=auth)
