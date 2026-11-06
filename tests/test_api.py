import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import models  # noqa: E402
from database import Base, get_db  # noqa: E402
from jose import jwt  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


def test_create_and_get_public_share_link():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Public Scan Share",
        "severity": "medium",
        "affected_component": "api",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert "share_url" in resp.json()
    share_url = resp.json()["share_url"]
    share_token = share_url.split("/")[-1]

    # Access anonymously without token or password
    public_resp = client.get(f"/share/{share_token}")
    assert public_resp.status_code == 200
    assert public_resp.json()["id"] == scan_id
    assert public_resp.json()["title"] == "Public Scan Share"


def test_create_and_get_password_protected_share():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Confidential Finding",
        "severity": "critical",
        "affected_component": "auth",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "SharePassword123!"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    share_url = resp.json()["share_url"]
    share_token = share_url.split("/")[-1]

    # Access without password
    no_pw_resp = client.get(f"/share/{share_token}")
    assert no_pw_resp.status_code == 401

    # Access with wrong password
    wrong_pw_resp = client.get(f"/share/{share_token}?password=WrongPassword")
    assert wrong_pw_resp.status_code == 401

    # Access with correct password
    correct_pw_resp = client.get(f"/share/{share_token}?password=SharePassword123!")
    assert correct_pw_resp.status_code == 200
    assert correct_pw_resp.json()["title"] == "Confidential Finding"


def test_get_shared_scan_expired():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Expired Finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = resp.json()["share_url"].split("/")[-1]

    # Force expiration in DB
    db = TestingSessionLocal()
    try:
        shared_link = db.query(models.SharedScanLink).filter(models.SharedScanLink.token == share_token).first()
        shared_link.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.commit()
    finally:
        db.close()

    expired_resp = client.get(f"/share/{share_token}")
    assert expired_resp.status_code == 410


def test_get_scan_unauthorized_bola():
    alice_token = register_and_login("alice_owner", "alice_o@example.com", "pw123")
    bob_token = register_and_login("bob_attacker", "bob_a@example.com", "pw123")

    # Alice creates a scan
    scan_id = client.post("/scans", json={
        "title": "Alice Confidential Report",
        "severity": "critical",
        "affected_component": "payment gateway",
    }, headers=auth_headers(alice_token)).json()["id"]

    # Bob tries to access Alice's scan
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(bob_token))
    assert resp.status_code == 404


def test_create_share_link_unauthorized_bola():
    alice_token = register_and_login("alice_share", "alice_s@example.com", "pw123")
    bob_token = register_and_login("bob_share", "bob_s@example.com", "pw123")

    # Alice creates a scan
    scan_id = client.post("/scans", json={
        "title": "Alice Internal Audit",
        "severity": "high",
        "affected_component": "auth module",
    }, headers=auth_headers(alice_token)).json()["id"]

    # Bob tries to generate a share link for Alice's scan
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(bob_token))
    assert resp.status_code == 404


def test_share_password_hashed_in_db():
    token = register_and_login("carol", "carol@example.com", "pw123")
    scan_id = client.post("/scans", json={
        "title": "Hashed Password Test",
        "severity": "medium",
        "affected_component": "db",
    }, headers=auth_headers(token)).json()["id"]

    raw_password = "SuperSecretPassword123!"
    resp = client.post(f"/scans/{scan_id}/share", json={"password": raw_password}, headers=auth_headers(token))
    share_token = resp.json()["share_url"].split("/")[-1]

    # Verify password is stored hashed in DB
    db = TestingSessionLocal()
    try:
        shared_link = db.query(models.SharedScanLink).filter(models.SharedScanLink.token == share_token).first()
        assert shared_link is not None
        assert shared_link.hashed_password != raw_password
        assert shared_link.hashed_password.startswith("$2b$") or shared_link.hashed_password.startswith("$2a$")
    finally:
        db.close()


def test_search_scans_sqli_protection():
    token = register_and_login("dave", "dave@example.com", "pw123")
    client.post("/scans", json={
        "title": "Normal Scan",
        "severity": "low",
        "affected_component": "frontend",
    }, headers=auth_headers(token))

    # Malicious SQL injection payload
    sqli_payload = "' OR '1'='1"
    resp = client.get(f"/scans/search?q={sqli_payload}", headers=auth_headers(token))
    assert resp.status_code == 200
    # Should safely return empty results, not dump all tables or throw SQL syntax errors
    assert len(resp.json()["results"]) == 0


def test_jwt_none_algorithm_rejected():
    import base64
    import json

    # Construct an unsigned token with "alg": "none" (classic JWT none attack)
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode()).decode().rstrip("=")
    forged_token = f"{header}.{payload}."

    resp = client.get("/scans", headers=auth_headers(forged_token))
    assert resp.status_code == 401
