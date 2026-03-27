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
_AUTH_EXEMPT = {"/v1/health", "/docs", "/v1/openapi.json", "/openapi.json", "/v1/keys/create", "/v1/demodemo"}

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
    """Validate a key via cache -> Turso -> env var fallback."""
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
        if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "")

        if not api_key or not await _validate_key(api_key):
            return JSONResponse(status_code=401, content=_INVALID_KEY_RESPONSE)

        # Attach key hash (never the key itself) to request state for logging
        request.state.api_key_hash = _hash_key(api_key)
        request.state.is_test_key = is_test_key(api_key)

        return await call_next(request)
