from .conftest import login


def test_login_success(client):
    assert login(client, "admin", "admin123!")


def test_login_failure_audited(client, admin):
    r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    logs = client.get("/api/v1/auth/audit", headers=admin).json()
    assert any(l["action"] == "auth.login" and l["result"] == "failure" for l in logs)


def test_rbac_viewer_cannot_create_user(client, viewer):
    r = client.post("/api/v1/auth/users",
                    json={"username": "x", "password": "password123", "role": "viewer"},
                    headers=viewer)
    assert r.status_code == 403


def test_admin_creates_user_and_login(client, admin):
    r = client.post("/api/v1/auth/users",
                    json={"username": "newbie", "password": "password123", "role": "viewer"},
                    headers=admin)
    assert r.status_code == 201
    assert login(client, "newbie", "password123")


def test_unauthenticated_rejected(client):
    assert client.get("/api/v1/events").status_code == 401


def test_password_min_length_enforced(client, admin):
    r = client.post("/api/v1/auth/users",
                    json={"username": "shorty", "password": "abc", "role": "viewer"}, headers=admin)
    assert r.status_code == 422
