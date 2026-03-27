"""
ClassiFinder — GET /v1/types

Returns all registered secret detection patterns with metadata.
Used for agent self-discovery and building type filter lists.
"""

from fastapi import APIRouter

from app.engine.patterns.registry import PATTERN_REGISTRY
from app.models.responses import TypeInfo, TypesResponse

router = APIRouter()


@router.get(
    "/v1/types",
    response_model=TypesResponse,
    summary="List all supported secret types",
    description=(
        "Returns metadata for all registered detection patterns. "
        "Use the returned `id` values to filter scan/redact requests to specific secret types."
    ),
)
async def list_types() -> TypesResponse:
    """Return all pattern metadata from the registry."""
    types = [
        TypeInfo(
            id=p.id,
            name=p.name,
            provider=p.provider,
            severity=p.severity,
            description=p.description,
            tags=p.tags,
        )
        for p in PATTERN_REGISTRY
    ]
    return TypesResponse(types_count=len(types), types=types)
