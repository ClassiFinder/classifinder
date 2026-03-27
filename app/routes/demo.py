"""
ClassiFinder — POST /v1/demodemo

Public demo endpoint for the landing page. No API key required.
Accepts small payloads only, returns redacted text and finding count.
Rate limited to 10 requests per IP per minute.

This exists so the landing page demo doesn't need a hardcoded API key
in its JavaScript source.
"""

import time
from collections import defaultdict
from typing import Dict, List

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field

from app.engine.scanner import scan
from app.engine.redactor import redact

router = APIRouter()

# ── Per-IP rate limiting (separate from the main rate limiter) ────────────
_demo_log: Dict[str, List[float]] = defaultdict(list)
_DEMO_RATE_LIMIT = 10  # requests per minute
_DEMO_WINDOW = 60  # seconds
_DEMO_MAX_BYTES = 1024  # 1 KB


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_demo_rate_limit(ip: str) -> None:
    now = time.monotonic()
    cutoff = now - _DEMO_WINDOW
    _demo_log[ip] = [t for t in _demo_log[ip] if t > cutoff]
    if len(_demo_log[ip]) >= _DEMO_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "demo_rate_limit",
                "message": "Demo rate limit exceeded. Sign up for a free API key for higher limits.",
                "retry_after": _DEMO_WINDOW,
            },
        )
    _demo_log[ip].append(now)


# ── Request/Response models (slim, demo-specific) ────────────────────────

class DemoRequest(BaseModel):
    text: str = Field(..., description="Text to scan and redact. Max 1 KB.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284",
            }
        }
    }


class DemoResponse(BaseModel):
    redacted_text: str
    findings_count: int
    scan_time_ms: int


# ── Endpoint ─────────────────────────────────────────────────────────────

@router.post(
    "/v1/demodemo",
    response_model=DemoResponse,
    summary="Demo: scan and redact (no auth required)",
    description=(
        "Public demo endpoint for the ClassiFinder landing page. "
        "No API key required. Max 1 KB payload. Rate limited to 10 req/min per IP. "
        "Returns redacted text and finding count only."
    ),
)
async def demo_redact(request: Request, body: DemoRequest) -> DemoResponse:
    """Public demo: redact secrets, no auth needed."""
    # Payload size check
    text_bytes = len(body.text.encode("utf-8"))
    if text_bytes > _DEMO_MAX_BYTES:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "payload_too_large",
                "message": f"Demo accepts max {_DEMO_MAX_BYTES} bytes. Sign up for a free API key to scan larger texts.",
            },
        )

    # Per-IP rate limit
    ip = _get_client_ip(request)
    _check_demo_rate_limit(ip)

    # Scan and redact
    t0 = time.monotonic()
    findings = scan(text=body.text, min_confidence=0.5, include_context=False)
    redacted_text, _ = redact(body.text, findings, style="label")
    scan_time_ms = int((time.monotonic() - t0) * 1000)

    return DemoResponse(
        redacted_text=redacted_text,
        findings_count=len(findings),
        scan_time_ms=scan_time_ms,
    )
