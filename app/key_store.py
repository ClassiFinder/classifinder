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
from typing import Tuple

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
            revoked_at TEXT,
            marketing_opt_in INTEGER NOT NULL DEFAULT 0
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

def create_key(email: str, ip_address: str, marketing_opt_in: bool = False) -> Tuple[str, str]:
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
        (ip_address, one_hour_ago),
    ).fetchone()
    if result and result[0] >= 5:
        raise PermissionError("IP rate limit exceeded")

    # Check email uniqueness among active keys
    result = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE email = ? AND revoked_at IS NULL",
        (email,),
    ).fetchone()
    if result and result[0] > 0:
        raise ValueError("Email already registered")

    raw_key = generate_key()
    key_hash = hash_key_full(raw_key)
    key_prefix = raw_key[:12]
    created_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    conn.execute(
        """INSERT INTO api_keys (key_hash, key_prefix, email, tier, created_by_ip, created_at, marketing_opt_in)
           VALUES (?, ?, ?, 'free', ?, ?, ?)""",
        (key_hash, key_prefix, email, ip_address, created_at, int(marketing_opt_in)),
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
            (key_hash,),
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
        (old_key_hash,),
    ).fetchone()
    if not result:
        raise ValueError("Key not found or already revoked")

    email = result[0]
    revoked_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    # Revoke old key
    conn.execute(
        "UPDATE api_keys SET revoked_at = ? WHERE key_hash = ?",
        (revoked_at, old_key_hash),
    )

    # Generate new key
    raw_key = generate_key()
    new_hash = hash_key_full(raw_key)
    key_prefix = raw_key[:12]
    created_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    conn.execute(
        """INSERT INTO api_keys (key_hash, key_prefix, email, tier, created_by_ip, created_at)
           VALUES (?, ?, ?, 'free', ?, ?)""",
        (new_hash, key_prefix, email, ip_address, created_at),
    )
    conn.commit()

    _cache_invalidate(old_key_hash)
    _cache_put(new_hash)

    return raw_key, email, created_at
