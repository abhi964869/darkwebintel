"""
tests/test_api.py — Backend Unit & Integration Tests
======================================================
Run: pytest tests/ -v

Requires:
  - Flask app running (or use test client)
  - A test MongoDB instance (uses "dark_web_intel_test" DB)
  - pip install pytest pytest-flask
"""

import pytest
import json
from bson import ObjectId
from app import create_app
from models import ensure_indexes

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    """Create a test Flask app using an isolated test DB."""
    import os
    os.environ["MONGO_URI"]      = "mongodb://localhost:27017/dark_web_intel_test"
    os.environ["JWT_SECRET_KEY"] = "test_secret_key_32chars_minimum!!"
    os.environ["FLASK_ENV"]      = "testing"

    application = create_app()
    application.config["TESTING"] = True

    # Ensure indexes exist
    db = application.config["DB"]
    ensure_indexes(db)

    yield application

    # Teardown — drop test DB after session
    db.client.drop_database("dark_web_intel_test")


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    return app.config["DB"]


@pytest.fixture
def analyst_token(client):
    """Register + login a test analyst, return JWT token."""
    client.post("/api/auth/register", json={
        "username": "testanalyst",
        "email":    "analyst@test.com",
        "password": "Secure1234!"
    })
    resp = client.post("/api/auth/login", json={
        "email":    "analyst@test.com",
        "password": "Secure1234!"
    })
    return json.loads(resp.data)["token"]


@pytest.fixture
def auth_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["status"] == "ok"


# ── Auth ──────────────────────────────────────────────────────────────────────

class TestAuth:
    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "newuser",
            "email":    "new@example.com",
            "password": "Password123!"
        })
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert "token" in data
        assert data["user"]["email"] == "new@example.com"
        # Password hash must never be returned
        assert "password_hash" not in data["user"]

    def test_register_duplicate_email(self, client):
        payload = {"username": "dup1", "email": "dup@test.com", "password": "Pass1234!"}
        client.post("/api/auth/register", json=payload)
        resp = client.post("/api/auth/register", json={**payload, "username": "dup2"})
        assert resp.status_code == 409

    def test_register_short_password(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "shortpw",
            "email":    "short@test.com",
            "password": "abc"
        })
        assert resp.status_code == 400

    def test_login_success(self, client):
        client.post("/api/auth/register", json={
            "username": "loginuser",
            "email":    "login@test.com",
            "password": "LoginPass1!"
        })
        resp = client.post("/api/auth/login", json={
            "email": "login@test.com", "password": "LoginPass1!"
        })
        assert resp.status_code == 200
        assert "token" in json.loads(resp.data)

    def test_login_wrong_password(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "analyst@test.com", "password": "wrongpassword"
        })
        assert resp.status_code == 401
        # Ensure vague error message
        assert "Invalid credentials" in json.loads(resp.data)["error"]

    def test_protected_endpoint_without_token(self, client):
        resp = client.get("/api/threats")
        assert resp.status_code == 401


# ── Threats ───────────────────────────────────────────────────────────────────

class TestThreats:
    def test_create_threat(self, client, auth_headers):
        resp = client.post("/api/threats", headers=auth_headers, json={
            "title":    "Test credential leak",
            "content":  "Sample threat content with details.",
            "severity": "high",
            "category": "credential_leak",
            "iocs":     ["192.168.1.1", "test@evil.com"],
        })
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["severity"] == "high"
        assert len(data["iocs"]) == 2
        return data["id"]

    def test_list_threats(self, client, auth_headers):
        resp = client.get("/api/threats", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "data" in data
        assert "total" in data
        assert isinstance(data["data"], list)

    def test_filter_by_severity(self, client, auth_headers):
        resp = client.get("/api/threats?severity=high", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        # All returned threats should have severity=high
        for t in data["data"]:
            assert t["severity"] == "high"

    def test_invalid_severity_filter(self, client, auth_headers):
        # Invalid severity should just be ignored, not crash
        resp = client.get("/api/threats?severity=extreme", headers=auth_headers)
        assert resp.status_code == 200

    def test_search_threats(self, client, auth_headers):
        # First create a threat with unique text
        client.post("/api/threats", headers=auth_headers, json={
            "title":    "xyzuniquekeyword2024 credential leak",
            "content":  "Searchable content here",
            "severity": "medium",
            "category": "data_breach",
        })
        resp = client.get("/api/threats/search?q=xyzuniquekeyword2024", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["count"] >= 1

    def test_search_short_query(self, client, auth_headers):
        resp = client.get("/api/threats/search?q=x", headers=auth_headers)
        assert resp.status_code == 400

    def test_get_threat_by_id(self, client, auth_headers, db):
        # Create one first
        r = client.post("/api/threats", headers=auth_headers, json={
            "title": "Get by ID test", "content": "content",
            "severity": "low", "category": "forum_post"
        })
        tid = json.loads(r.data)["id"]
        resp = client.get(f"/api/threats/{tid}", headers=auth_headers)
        assert resp.status_code == 200
        assert json.loads(resp.data)["id"] == tid

    def test_get_threat_invalid_id(self, client, auth_headers):
        resp = client.get("/api/threats/notanobjectid", headers=auth_headers)
        assert resp.status_code == 400


# ── Keywords & Alerts ─────────────────────────────────────────────────────────

class TestKeywords:
    def test_add_keyword(self, client, auth_headers):
        resp = client.post("/api/alerts/keywords", headers=auth_headers, json={
            "keyword":  "acmecorp",
            "category": "brand",
        })
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["keyword"] == "acmecorp"

    def test_add_duplicate_keyword(self, client, auth_headers):
        client.post("/api/alerts/keywords", headers=auth_headers, json={"keyword": "dupkeyword"})
        resp = client.post("/api/alerts/keywords", headers=auth_headers, json={"keyword": "dupkeyword"})
        assert resp.status_code == 409

    def test_add_invalid_regex(self, client, auth_headers):
        resp = client.post("/api/alerts/keywords", headers=auth_headers, json={
            "keyword": "[invalid(regex",
            "is_regex": True
        })
        assert resp.status_code == 400

    def test_list_keywords(self, client, auth_headers):
        resp = client.get("/api/alerts/keywords", headers=auth_headers)
        assert resp.status_code == 200
        assert "data" in json.loads(resp.data)

    def test_delete_keyword(self, client, auth_headers):
        r = client.post("/api/alerts/keywords", headers=auth_headers, json={"keyword": "deleteme"})
        kid = json.loads(r.data)["id"]
        resp = client.delete(f"/api/alerts/keywords/{kid}", headers=auth_headers)
        assert resp.status_code == 200


# ── Dashboard ─────────────────────────────────────────────────────────────────

class TestDashboard:
    def test_stats_endpoint(self, client, auth_headers):
        resp = client.get("/api/dashboard/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        for key in ["total_threats", "critical", "high", "new_alerts", "last_24h"]:
            assert key in data

    def test_trends_endpoint(self, client, auth_headers):
        resp = client.get("/api/dashboard/trends", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_categories_endpoint(self, client, auth_headers):
        resp = client.get("/api/dashboard/categories", headers=auth_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        for item in data["data"]:
            assert "category" in item and "count" in item

    def test_top_iocs_endpoint(self, client, auth_headers):
        resp = client.get("/api/dashboard/top-iocs", headers=auth_headers)
        assert resp.status_code == 200
        assert "data" in json.loads(resp.data)


# ── Ingestor Unit Tests ───────────────────────────────────────────────────────

class TestIngestor:
    def test_generate_simulated_threat_schema(self):
        from ingestor import generate_simulated_threat
        t = generate_simulated_threat()
        required_fields = ["title", "content", "source", "source_url",
                           "category", "severity", "iocs", "tags",
                           "processed", "created_at"]
        for field in required_fields:
            assert field in t, f"Missing field: {field}"

    def test_severity_is_valid(self):
        from ingestor import generate_simulated_threat
        valid = {"low", "medium", "high", "critical"}
        for _ in range(20):
            t = generate_simulated_threat()
            assert t["severity"] in valid

    def test_random_iocs_format(self):
        from ingestor import random_iocs
        iocs = random_iocs(10)
        assert len(iocs) == 10
        for ioc in iocs:
            assert isinstance(ioc, str) and len(ioc) > 0

    def test_keyword_matching(self, app, db):
        from ingestor import match_keywords
        from models import new_keyword, new_user, utcnow
        import bcrypt

        # Create a test user
        user = new_user("kwuser", "kwuser@test.com",
                        bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode())
        uid = db.users.insert_one(user).inserted_id

        # Add keyword
        kw = new_keyword(uid, "globalbank")
        db.keywords.insert_one(kw)

        # Create a threat containing that keyword
        from models import new_threat
        threat = new_threat(
            title="GlobalBank data stolen",
            content="We are selling globalbank credentials for 0.5 BTC",
            source="sim",
            source_url="http://fake.onion/1",
            category="credential_leak",
            severity="high",
        )
        tid = db.threats.insert_one(threat).inserted_id

        count = match_keywords(db, threat, tid)
        assert count >= 1

        # Alert should exist in DB
        alert = db.alerts.find_one({"threat_id": tid, "keyword": "globalbank"})
        assert alert is not None
        assert alert["status"] == "new"
