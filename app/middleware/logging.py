"""
ClassiFinder — Request Metadata Logger

Logs structured metadata for every request. NEVER logs request bodies,
response bodies, or any secret values — only safe operational metadata.

Logged fields:
  request_id, api_key_hash, timestamp, endpoint, method,
  input_size_bytes, finding_count, response_time_ms, status_code
"""

import json
import time
import sys

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class LoggingMiddleware(BaseHTTPMiddleware):
    """Emit one JSON log line per request with metadata only."""

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()

        response = await call_next(request)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        content_length = request.headers.get("content-length", "0")

        log_entry = {
            "request_id": getattr(request.state, "request_id", None),
            "api_key_hash": getattr(request.state, "api_key_hash", None),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": request.method,
            "endpoint": request.url.path,
            "input_size_bytes": int(content_length) if content_length.isdigit() else 0,
            "finding_count": getattr(request.state, "finding_count", None),
            "response_time_ms": elapsed_ms,
            "status_code": response.status_code,
        }

        print(json.dumps(log_entry), file=sys.stdout, flush=True)

        return response
