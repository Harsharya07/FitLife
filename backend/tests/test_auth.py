def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["app"] == "FitLife API"


def test_signup_and_login(client):
    resp = client.post(
        "/api/auth/signup",
        json={"username": "alice", "password": "pass1234", "confirm_password": "pass1234"},
    )
    assert resp.status_code == 200

    resp = client.post("/api/auth/login", json={"username": "alice", "password": "pass1234"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_signup_password_mismatch(client):
    resp = client.post(
        "/api/auth/signup",
        json={"username": "bob", "password": "pass1234", "confirm_password": "wrong"},
    )
    assert resp.status_code == 400


def test_protected_route_requires_auth(client):
    resp = client.get("/api/content/exercises")
    assert resp.status_code == 401


def test_refresh_token_flow(client):
    client.post(
        "/api/auth/signup",
        json={"username": "carol", "password": "pass1234", "confirm_password": "pass1234"},
    )
    login = client.post("/api/auth/login", json={"username": "carol", "password": "pass1234"})
    refresh = login.json()["refresh_token"]

    resp = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_admin_user(client):
    client.post(
        "/api/auth/signup",
        json={"username": "admin", "password": "pass1234", "confirm_password": "pass1234"},
    )
    login = client.post("/api/auth/login", json={"username": "admin", "password": "pass1234"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me = client.get("/api/auth/me", headers=headers)
    assert me.json()["is_admin"] is True

    contacts = client.get("/api/admin/contacts", headers=headers)
    assert contacts.status_code == 200
