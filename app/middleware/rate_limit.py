"""
ClassiFinder — In-Memory Rate Limiter

Sliding window rate limiter keyed by API key hash. Stores timestamps of recent
requests in a dict; drops entries older than 60 seconds on each check.

MVP design: single process, no Redis. Thread-safe via asyncio (single-threaded
event loop). Not suitable for multi-process deployments without a shared store.
"""

import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings

# Endpoints exempt from rate limiting (health check is unauthenticated anyway)
_RATE_LIMIT_EXEMPT = {"/v1/health"}

# {api_key_hash: deque([timestamp, ...])} — sorted ascending, oldest at left.
# Deque enables amortized O(1) expiration via popleft() vs O(R) list filter rebuild.
_request_log: Dict[str, Deque[float]] = defaultdict(deque)

WINDOW_SECONDS = 60


def reset_request_log() -> None:
    """Clear the rate-limit state. Used in tests."""
    _request_log.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-key request rate limits using a sliding window."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _RATE_LIMIT_EXEMPT:
            return await call_next(request)

        # Auth middleware runs first and sets this; if missing, skip (auth will reject)
        key_hash = getattr(request.state, "api_key_hash", None)
        if key_hash is None:
            return await call_next(request)

        settings = get_settings()
        limit = settings.rate_limit_per_minute
        now = time.monotonic()

        # Slide the window: amortized O(1) per request via popleft of expired entries.
        # Timestamps are appended in monotonic order, so leading entries are always oldest.
        timestamps = _request_log[key_hash]
        cutoff = now - WINDOW_SECONDS
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        remaining = limit - len(timestamps)
        reset_at = int(time.time()) + WINDOW_SECONDS

        if remaining <= 0:
            retry_after = WINDOW_SECONDS - int(now - timestamps[0])
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(max(1, retry_after))},
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": f"You have exceeded your rate limit of {limit} requests per minute.",
                        "retry_after": max(1, retry_after),
                    }
                },
            )

        # Record this request
        timestamps.append(now)
        remaining -= 1

        response = await call_next(request)

        # Attach rate limit headers to every successful response
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(reset_at)

        return response
