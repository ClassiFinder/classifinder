# Key Provisioning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add self-serve API key provisioning with Turso storage, in-memory caching, and graceful degradation.

**Architecture:** New `key_store.py` module handles all Turso interaction (init, create, lookup, revoke). Auth middleware gains a three-step lookup: LRU cache → Turso → env var fallback. Two new endpoints (`/v1/keys/create`, `/v1/keys/rotate`). Turso calls run via `asyncio.to_thread()` to avoid blocking.

**Tech Stack:** Turso (hosted SQLite) via `libsql-experimental`, FastAPI, existing middleware patterns

**Spec:** `docs/specs/2026-03-23-key-provisioning-design.md`

**Working directory:** `/Users/thomasparas/Documents/ClassiFinder/classifinder/`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `app/config.py` | Modify | Add optional `turso_database_url` and `turso_auth_token` settings |
| `app/key_store.py` | Create | Turso client, init_db, key generation, hash storage, lookup, cache, revoke |
| `app/models/requests.py` | Modify | Add `KeyCreateRequest` |
| `app/models/responses.py` | Modify | Add `KeyCreateResponse` |
| `app/middleware/auth.py` | Modify | Three-step lookup: cache → Turso → env var |
| `app/routes/keys.py` | Create | `POST /v1/keys/create` and `POST /v1/keys/rotate` |
| `app/main.py` | Modify | Register keys router, auth exempt, lifespan init_db |
| `requirements.txt` | Modify | Add `libsql-experimental` |
| `tests/test_keys.py` | Create | All key provisioning tests |

---

## Task 1: Config and dependency

**Files:**
- Modify: `app/config.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Add Turso settings to config.py**

Add these lines to `Settings.__init__` (after `self.app_name`):

```python
        # Turso (optional — key provisioning disabled if absent)
        self.turso_database_url = os.environ.get("TURSO_DATABASE_URL", "")
        self.turso_auth_token = os.environ.get("TURSO_AUTH_TOKEN", "")
        self.turso_enabled = bool(self.turso_database_url and self.turso_auth_token)
```

- [ ] **Step 2: Add libsql-experimental to requirements.txt**

Append: `libsql-experimental>=0.0.54`

- [ ] **Step 3: Install**

```bash
pip install libsql-experimental
```

- [ ] **Step 4: Verify existing tests still pass**

```bash
python -m pytest tests/ -v
```

- [ ] **Step 5: Commit**

```bash
git add app/config.py requirements.txt
git commit -m "config: add optional Turso settings and libsql dependency"
```

---

## Task 2: Key store module

**Files:**
- Create: `app/key_store.py`

This is the core module — all Turso interaction is isolated here.

- [ ] **Step 1: Create app/key_store.py**

```python
"""
ClassiFinder — Key Store

Manages API key lifecycle: generation, storage, lookup, and revocation.
Uses Turso (hosted SQLite) for persistence and an in-memory LRU cache
for fast lookups. All Turso calls are synchronous and must be run via
asyncio.to_thread() from async contexts.

If Turso is not configured, all operations raise RuntimeError.
"""

import hashlib
import secrets
import time
from typing import Optional, Tuple

import libsql_experimental as libsql

from app.config import get_settings

# ── In-memory cache ──────────────────────────────────────────────────────────
# Maps key_hash (str) → expiry timestamp (float). If present and not expired,
# the key is valid without hitting Turso.

_cache: dict[str, float] = {}
_CACHE_TTL = 60.0  # seconds
_CACHE_MAX_SIZE = 1024


def _cache_get(key_hash: str) -> bool:
    """Check if a key hash is in the cache and not expired."""
    expiry = _cache.get(key_hash)
    if expiry is None:
        return False
    if time.monotonic() > expiry:
        _cache.pop(key_hash, None)
        return False
    return True


def _cache_put(key_hash: str) -> None:
    """Add a key hash to the cache with TTL."""
    if len(_cache) >= _CACHE_MAX_SIZE:
        # Evict oldest entries (simplistic — fine for 1024 keys)
        expired = [k for k, v in _cache.items() if time.monotonic() > v]
        for k in expired:
            _cache.pop(k, None)
        if len(_cache) >= _CACHE_MAX_SIZE:
            # Still full — evict first entry
            _cache.pop(next(iter(_cache)), None)
    _cache[key_hash] = time.monotonic() + _CACHE_TTL


def _cache_invalidate(key_hash: str) -> None:
    """Remove a key hash from the cache."""
    _cache.pop(key_hash, None)


def cache_clear() -> None:
    """Clear the entire cache. Used in tests."""
    _cache.clear()


# ── Hashing ──────────────────────────────────────────────────────────────────

def hash_key_full(key: str) -> str:
    """Return the full SHA-256 hex digest of an API key (64 chars)."""
    return hashlib.sha256(key.encode()).hexdigest()


# ── Database ─────────────────────────────────────────────────────────────────

_db_conn = None


def _get_conn():
    """Get or create the Turso database connection."""
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    settings = get_settings()
    if not settings.turso_enabled:
        raise RuntimeError("Turso is not configured")
    _db_conn = libsql.connect(
        settings.turso_database_url,
        auth_token=settings.turso_auth_token,
    )
    return _db_conn


def reset_conn() -> None:
    """Reset the connection. Used in tests."""
    global _db_conn
    _db_conn = None


def init_db() -> None:
    """Create the api_keys table if it doesn't exist. Called during app startup."""
    settings = get_settings()
    if not settings.turso_enabled:
        return
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_hash TEXT PRIMARY KEY,
            key_prefix TEXT NOT NULL,
            email TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free',
            created_by_ip TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)
    # SQLite partial unique index
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_email_active
        ON api_keys(email) WHERE revoked_at IS NULL
    """)
    conn.commit()


# ── Key generation ───────────────────────────────────────────────────────────

def generate_key() -> str:
    """Generate a new API key: ss_live_ + 40 random hex chars."""
    return "ss_live_" + secrets.token_hex(20)


# ── Key operations (synchronous — call via asyncio.to_thread) ────────────────

def create_key(email: str, ip_address: str) -> Tuple[str, str]:
    """Create a new API key for the given email.

    Returns (raw_key, created_at). The raw key is returned once and never stored.
    Raises ValueError if email already has an active key.
    Raises RuntimeError if Turso is not configured.
    """
    import time as _time

    conn = _get_conn()

    # Check IP rate limit: 5 keys per IP per hour
    one_hour_ago = _time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", _time.gmtime(_time.time() - 3600)
    )
    result = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE created_by_ip = ? AND created_at > ?",
        [ip_address, one_hour_ago],
    ).fetchone()
    if result and result[0] >= 5:
        raise PermissionError("IP rate limit exceeded")

    # Check email uniqueness among active keys
    result = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE email = ? AND revoked_at IS NULL",
        [email],
    ).fetchone()
    if result and result[0] > 0:
        raise ValueError("Email already registered")

    raw_key = generate_key()
    key_hash = hash_key_full(raw_key)
    key_prefix = raw_key[:12]
    created_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    conn.execute(
        """INSERT INTO api_keys (key_hash, key_prefix, email, tier, created_by_ip, created_at)
           VALUES (?, ?, ?, 'free', ?, ?)""",
        [key_hash, key_prefix, email, ip_address, created_at],
    )
    conn.commit()

    _cache_put(key_hash)

    return raw_key, created_at


def lookup_key(key_hash: str) -> bool:
    """Check if a key hash exists and is not revoked. Returns True/False.

    Checks in-memory cache first. On cache miss, queries Turso.
    """
    if _cache_get(key_hash):
        return True

    try:
        conn = _get_conn()
        result = conn.execute(
            "SELECT 1 FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            [key_hash],
        ).fetchone()
        if result:
            _cache_put(key_hash)
            return True
        return False
    except Exception:
        return False  # Turso down — fall through to env var


def rotate_key(old_key_hash: str, ip_address: str) -> Tuple[str, str, str]:
    """Revoke the old key and create a new one for the same email.

    Returns (new_raw_key, email, created_at).
    Raises ValueError if old key not found.
    """
    import time as _time

    conn = _get_conn()

    # Find the old key's email
    result = conn.execute(
        "SELECT email FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
        [old_key_hash],
    ).fetchone()
    if not result:
        raise ValueError("Key not found or already revoked")

    email = result[0]
    revoked_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    # Revoke old key
    conn.execute(
        "UPDATE api_keys SET revoked_at = ? WHERE key_hash = ?",
        [revoked_at, old_key_hash],
    )

    # Generate new key
    raw_key = generate_key()
    new_hash = hash_key_full(raw_key)
    key_prefix = raw_key[:12]
    created_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    conn.execute(
        """INSERT INTO api_keys (key_hash, key_prefix, email, tier, created_by_ip, created_at)
           VALUES (?, ?, ?, 'free', ?, ?)""",
        [new_hash, key_prefix, email, ip_address, created_at],
    )
    conn.commit()

    _cache_invalidate(old_key_hash)
    _cache_put(new_hash)

    return raw_key, email, created_at
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from app.key_store import generate_key, hash_key_full; print(generate_key()); print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add app/key_store.py
git commit -m "feat: key store module with Turso integration and LRU cache"
```

---

## Task 3: Pydantic models for key endpoints

**Files:**
- Modify: `app/models/requests.py`
- Modify: `app/models/responses.py`

- [ ] **Step 1: Add KeyCreateRequest to requests.py**

Append to `app/models/requests.py`:

```python
class KeyCreateRequest(BaseModel):
    """Request body for POST /v1/keys/create."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "developer@example.com",
            }
        }
    }

    email: str = Field(..., description="Email address to associate with the API key.")

    @model_validator(mode="after")
    def validate_and_normalize_email(self) -> "KeyCreateRequest":
        email = self.email.strip().lower()
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError("Invalid email address.")
        self.email = email
        return self
```

- [ ] **Step 2: Add KeyCreateResponse to responses.py**

Append to `app/models/responses.py`:

```python
class KeyCreateResponse(BaseModel):
    """Response body for POST /v1/keys/create and /v1/keys/rotate."""

    api_key: str = Field(..., description="The generated API key. Save it — you will not see it again.")
    email: str = Field(..., description="The email associated with this key.")
    created_at: str = Field(..., description="ISO 8601 timestamp.")
    message: str = Field(default="Save this key — you will not see it again.")
```

- [ ] **Step 3: Verify existing tests still pass**

```bash
python -m pytest tests/ -v
```

- [ ] **Step 4: Commit**

```bash
git add app/models/requests.py app/models/responses.py
git commit -m "feat: Pydantic models for key create/rotate endpoints"
```

---

## Task 4: Auth middleware — three-step lookup

**Files:**
- Modify: `app/middleware/auth.py`

- [ ] **Step 1: Rewrite auth.py**

Replace the entire contents of `app/middleware/auth.py`:

```python
"""
ClassiFinder — API Key Authentication

Three-step key validation:
1. In-memory LRU cache (fast, 60s TTL)
2. Turso database lookup (via asyncio.to_thread)
3. Fallback to CLASSIFINDER_API_KEYS env var (admin keys)

If Turso is down, logs a warning and falls through to env var.
"""

import asyncio
import hashlib
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.key_store import hash_key_full, lookup_key

logger = logging.getLogger("classifinder.auth")

# Endpoints that skip auth entirely
_AUTH_EXEMPT = {"/v1/health", "/docs", "/v1/openapi.json", "/openapi.json", "/v1/keys/create"}

_INVALID_KEY_RESPONSE = {
    "error": {
        "code": "invalid_api_key",
        "message": "Missing, malformed, or revoked API key. "
                   "Pass your key in the X-API-Key header.",
        "retry_after": None,
    }
}


def _hash_key(key: str) -> str:
    """Return the first 8 hex chars of the SHA-256 hash (for logging only)."""
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def is_test_key(key: str) -> bool:
    """Return True if the key uses the sandbox prefix."""
    return key.startswith("ss_test_")


async def _validate_key(api_key: str) -> bool:
    """Validate a key via cache → Turso → env var fallback."""
    settings = get_settings()

    # Step 1 + 2: Cache and Turso (lookup_key handles both)
    if settings.turso_enabled:
        try:
            key_hash = hash_key_full(api_key)
            found = await asyncio.to_thread(lookup_key, key_hash)
            if found:
                return True
        except Exception as exc:
            logger.warning("Turso lookup failed, falling through to env var: %s", exc)

    # Step 3: Env var fallback
    if api_key in settings.api_keys:
        return True

    return False


class AuthMiddleware(BaseHTTPMiddleware):
    """Validate X-API-Key on all non-exempt endpoints."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _AUTH_EXEMPT:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "")

        if not api_key or not await _validate_key(api_key):
            return JSONResponse(status_code=401, content=_INVALID_KEY_RESPONSE)

        # Attach key hash (never the key itself) to request state for logging
        request.state.api_key_hash = _hash_key(api_key)
        request.state.is_test_key = is_test_key(api_key)

        return await call_next(request)
```

- [ ] **Step 2: Verify existing tests pass** (auth tests use env var keys which still work via fallback)

```bash
python -m pytest tests/test_api.py -v
```

- [ ] **Step 3: Commit**

```bash
git add app/middleware/auth.py
git commit -m "feat: three-step auth — cache, Turso, env var fallback"
```

---

## Task 5: Keys router

**Files:**
- Create: `app/routes/keys.py`

- [ ] **Step 1: Create app/routes/keys.py**

```python
"""
ClassiFinder — Key Provisioning Routes

POST /v1/keys/create — Generate a new API key (no auth required)
POST /v1/keys/rotate — Revoke old key, issue new one (auth required)
"""

import asyncio

from fastapi import APIRouter, Request, HTTPException

from app.config import get_settings
from app.key_store import create_key, rotate_key, hash_key_full
from app.models.requests import KeyCreateRequest
from app.models.responses import KeyCreateResponse

router = APIRouter()


def _get_client_ip(request: Request) -> str:
    """Extract client IP from X-Forwarded-For or fall back to client.host."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post(
    "/v1/keys/create",
    response_model=KeyCreateResponse,
    status_code=201,
    summary="Create a new API key",
    description="Generate a new API key for the given email. No authentication required. Rate limited to 1 key per email and 5 keys per IP per hour.",
)
async def create_api_key(request: Request, body: KeyCreateRequest) -> KeyCreateResponse:
    """Generate and return a new API key."""
    settings = get_settings()

    if not settings.turso_enabled:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "key_provisioning_unavailable",
                "message": "Key provisioning is not configured.",
            },
        )

    ip_address = _get_client_ip(request)

    try:
        raw_key, created_at = await asyncio.to_thread(
            create_key, body.email, ip_address
        )
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "email_already_registered",
                "message": "An API key already exists for this email address.",
            },
        )
    except PermissionError:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "key_creation_rate_limit",
                "message": "Too many key creation requests. Try again later.",
                "retry_after": 3600,
            },
        )

    return KeyCreateResponse(
        api_key=raw_key,
        email=body.email,
        created_at=created_at,
        message="Save this key — you will not see it again.",
    )


@router.post(
    "/v1/keys/rotate",
    response_model=KeyCreateResponse,
    summary="Rotate an API key",
    description="Revoke the current key and issue a new one for the same email. Requires authentication with the current key.",
)
async def rotate_api_key(request: Request) -> KeyCreateResponse:
    """Revoke the old key and return a new one."""
    settings = get_settings()

    if not settings.turso_enabled:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "key_provisioning_unavailable",
                "message": "Key provisioning is not configured.",
            },
        )

    api_key = request.headers.get("X-API-Key", "")
    old_hash = hash_key_full(api_key)
    ip_address = _get_client_ip(request)

    try:
        raw_key, email, created_at = await asyncio.to_thread(
            rotate_key, old_hash, ip_address
        )
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "key_not_found",
                "message": "Key not found or already revoked. Only Turso-provisioned keys can be rotated.",
            },
        )

    return KeyCreateResponse(
        api_key=raw_key,
        email=email,
        created_at=created_at,
        message="Previous key has been revoked. Save this new key — you will not see it again.",
    )
```

- [ ] **Step 2: Commit**

```bash
git add app/routes/keys.py
git commit -m "feat: key create and rotate endpoints"
```

---

## Task 6: Wire up in main.py

**Files:**
- Modify: `app/main.py`

- [ ] **Step 1: Add keys router import**

Add to the import block at the top of main.py:

```python
from app.routes import health, types, scan, redact, feedback, keys
```

- [ ] **Step 2: Update lifespan to init Turso**

Replace the lifespan function:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize Turso if configured."""
    from app.key_store import init_db
    init_db()
    yield
```

- [ ] **Step 3: Add keys router**

Add after the feedback router line:

```python
    app.include_router(keys.router)
```

- [ ] **Step 4: Verify existing tests still pass**

```bash
python -m pytest tests/ -v
```

- [ ] **Step 5: Commit**

```bash
git add app/main.py
git commit -m "feat: register keys router and Turso init in lifespan"
```

---

## Task 7: Tests

**Files:**
- Create: `tests/test_keys.py`

- [ ] **Step 1: Create tests/test_keys.py**

```python
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
```

- [ ] **Step 2: Run tests**

```bash
python -m pytest tests/test_keys.py -v
```

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest tests/ -v
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_keys.py
git commit -m "test: key provisioning — create, rotate, auth, rate limits"
```

---

## Summary

| Task | What it builds | Files |
|------|---------------|-------|
| 1 | Config + dependency | config.py, requirements.txt |
| 2 | Key store module | key_store.py |
| 3 | Pydantic models | requests.py, responses.py |
| 4 | Auth middleware rewrite | auth.py |
| 5 | Keys router | routes/keys.py |
| 6 | Wire up in main.py | main.py |
| 7 | Tests | test_keys.py |
