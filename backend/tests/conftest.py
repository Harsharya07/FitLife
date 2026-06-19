import pytest
from fastapi.testclient import TestClient

from app.database import init_db


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.database.DB_PATH", db_file)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-pytest")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    init_db()
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def auth_headers(client):
    client.post(
        "/api/auth/signup",
        json={"username": "testuser", "password": "secret123", "confirm_password": "secret123"},
    )
    resp = client.post("/api/auth/login", json={"username": "testuser", "password": "secret123"})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
