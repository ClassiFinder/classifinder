"""
ClassiFinder — Key Provisioning Tests

Tests key creation, duplicate email rejection, IP rate limiting,
key rotation, auth lookup with Turso, and Turso-down fallback.

Uses an in-memory SQLite database (not real Turso) for test isolation.
"""

import os
import pytest

# Ensure test env vars are set before importing the app
os.environ.setdefault("CLASSIFINDER_API_KEYS", "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx")

from fastapi.testclient import TestClient
from app.config import get_settings

# We need to set up a local SQLite for tests instead of Turso
# Override the key_store module to use a local file
import app.key_store as key_store


TEST_KEY = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
HEADERS = {"X-API-Key": TEST_KEY}


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Set up a fresh in-memory SQLite DB for each test."""
    import libsql_experimental as libsql

    db_path = str(tmp_path / "test.db")

    # Reset module state
    key_store.reset_conn()
    key_store.cache_clear()

    # Patch settings to enable Turso with local SQLite
    monkeypatch.setenv("TURSO_DATABASE_URL", f"file:{db_path}")
    monkeypatch.setenv("TURSO_AUTH_TOKEN", "test")
    monkeypatch.setenv("CLASSIFINDER_API_KEYS", TEST_KEY)
    monkeypatch.setenv("CLASSIFINDER_RATE_LIMIT_PER_MINUTE", "1000")

    # Clear settings cache so new env vars are picked up
    get_settings.cache_clear()

    # Patch the connection to use local SQLite
    conn = libsql.connect(db_path)
    key_store._db_conn = conn

    # Override turso_enabled
    settings = get_settings()
    monkeypatch.setattr(settings, "turso_enabled", True)

    # Init the schema
    key_store.init_db()

    yield

    # Cleanup
    key_store.reset_conn()
    key_store.cache_clear()
    get_settings.cache_clear()


@pytest.fixture
def client():
    """Fresh test client per test (picks up patched settings)."""
    from app.main import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


class TestKeyCreate:
    def test_create_key_success(self, client):
        r = client.post("/v1/keys/create", json={"email": "test@example.com"})
        assert r.status_code == 201
        data = r.json()
        assert data["api_key"].startswith("ss_live_")
        assert len(data["api_key"]) == 48
        assert data["email"] == "test@example.com"
        assert "created_at" in data
        assert "Save this key" in data["message"]

    def test_create_key_normalizes_email(self, client):
        r = client.post("/v1/keys/create", json={"email": "  Test@Example.COM  "})
        assert r.status_code == 201
        assert r.json()["email"] == "test@example.com"

    def test_create_key_duplicate_email(self, client):
        client.post("/v1/keys/create", json={"email": "dupe@example.com"})
        r = client.post("/v1/keys/create", json={"email": "dupe@example.com"})
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "email_already_registered"

    def test_create_key_invalid_email(self, client):
        r = client.post("/v1/keys/create", json={"email": "not-an-email"})
        assert r.status_code in (400, 422)

    def test_create_key_missing_email(self, client):
        r = client.post("/v1/keys/create", json={})
        assert r.status_code in (400, 422)

    def test_create_key_no_auth_required(self, client):
        """The create endpoint should work without an API key."""
        r = client.post("/v1/keys/create", json={"email": "noauth@example.com"})
        assert r.status_code == 201


class TestKeyRotate:
    def test_rotate_key(self, client):
        # Create a key first
        r = client.post("/v1/keys/create", json={"email": "rotate@example.com"})
        old_key = r.json()["api_key"]

        # Rotate it
        r = client.post("/v1/keys/rotate", headers={"X-API-Key": old_key})
        assert r.status_code == 200
        data = r.json()
        assert data["api_key"].startswith("ss_live_")
        assert data["api_key"] != old_key
        assert data["email"] == "rotate@example.com"
        assert "revoked" in data["message"].lower()

    def test_old_key_invalid_after_rotate(self, client):
        # Create and rotate
        r = client.post("/v1/keys/create", json={"email": "oldkey@example.com"})
        old_key = r.json()["api_key"]
        r = client.post("/v1/keys/rotate", headers={"X-API-Key": old_key})
        new_key = r.json()["api_key"]

        # Old key should fail on scan
        key_store.cache_clear()
        r = client.post("/v1/scan", json={"text": "test"}, headers={"X-API-Key": old_key})
        assert r.status_code == 401

        # New key should work
        r = client.post("/v1/scan", json={"text": "test"}, headers={"X-API-Key": new_key})
        assert r.status_code == 200

    def test_rotate_requires_auth(self, client):
        r = client.post("/v1/keys/rotate")
        assert r.status_code == 401


class TestAuthWithTurso:
    def test_turso_provisioned_key_works(self, client):
        r = client.post("/v1/keys/create", json={"email": "auth@example.com"})
        key = r.json()["api_key"]

        r = client.post("/v1/scan", json={"text": "hello"}, headers={"X-API-Key": key})
        assert r.status_code == 200

    def test_env_var_key_still_works(self, client):
        """Admin keys from CLASSIFINDER_API_KEYS should still authenticate."""
        r = client.post("/v1/scan", json={"text": "hello"}, headers=HEADERS)
        assert r.status_code == 200


class TestIPRateLimit:
    def test_ip_rate_limit(self, client):
        """After 5 keys from the same IP, the 6th should be rejected."""
        for i in range(5):
            r = client.post("/v1/keys/create", json={"email": f"user{i}@example.com"})
            assert r.status_code == 201

        r = client.post("/v1/keys/create", json={"email": "user5@example.com"})
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "key_creation_rate_limit"
