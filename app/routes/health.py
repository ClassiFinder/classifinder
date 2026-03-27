"""
ClassiFinder — GET /v1/health

No auth required. Returns service status, version, pattern count, and uptime.
"""

import time
from fastapi import APIRouter

from app.config import get_settings
from app.engine.patterns.registry import PATTERN_REGISTRY
from app.models.responses import HealthResponse

router = APIRouter()

_start_time = time.monotonic()


@router.get(
    "/v1/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns service status, version, pattern count, and uptime. No authentication required.",
)
async def health() -> HealthResponse:
    """Return current service health."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        patterns_loaded=len(PATTERN_REGISTRY),
        uptime_seconds=int(time.monotonic() - _start_time),
    )
