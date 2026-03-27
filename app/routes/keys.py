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
    description="Generate a new API key for the given email. No authentication required. "
                "Rate limited to 1 key per email and 5 keys per IP per hour.",
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
            create_key, body.email, ip_address, body.subscribe
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
    description="Revoke the current key and issue a new one for the same email. "
                "Requires authentication with the current key.",
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
                "message": "Key not found or already revoked. "
                           "Only Turso-provisioned keys can be rotated.",
            },
        )

    return KeyCreateResponse(
        api_key=raw_key,
        email=email,
        created_at=created_at,
        message="Previous key has been revoked. Save this new key — you will not see it again.",
    )
