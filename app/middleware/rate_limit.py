"""
ClassiFinder — In-Memory Rate Limiter

Sliding window rate limiter keyed by API key hash. Stores timestamps of recent
requests in a dict; drops entries older than 60 seconds on each check.

MVP design: single process, no Redis. Thread-safe via asyncio (single-threaded
event loop). Not suitable for multi-process deployments without a shared store.
"""

import time
from collections import defaultdict
from typing import Dict, List

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings

# Endpoints exempt from rate limiting (health check is unauthenticated anyway)
_RATE_LIMIT_EXEMPT = {"/v1/health"}

# {api_key_hash: [timestamp, ...]}
_request_log: Dict[str, List[float]] = defaultdict(list)

WINDOW_SECONDS = 60


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

        # Slide the window
        timestamps = _request_log[key_hash]
        cutoff = now - WINDOW_SECONDS
        _request_log[key_hash] = [t for t in timestamps if t > cutoff]

        remaining = limit - len(_request_log[key_hash])
        reset_at = int(time.time()) + WINDOW_SECONDS

        if remaining <= 0:
            retry_after = WINDOW_SECONDS - int(now - _request_log[key_hash][0])
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
        _request_log[key_hash].append(now)
        remaining -= 1

        response = await call_next(request)

        # Attach rate limit headers to every successful response
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(reset_at)

        return response
