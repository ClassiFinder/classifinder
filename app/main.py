"""
ClassiFinder API — FastAPI Application Entry Point

Wires up routers, middleware (auth → rate limit → logging), CORS, and
global exception handlers. The engine is a pure function and is never
initialized here — it's imported on first use.

Run with:
    uvicorn app.main:app --reload --port 8000
"""

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.config import get_settings
from app.middleware.auth import AuthMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.logging import LoggingMiddleware
from app.routes import health, types, scan, redact, feedback, keys, demo


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize Turso tables if configured."""
    from app.key_store import init_db
    from app.feedback_store import init_feedback_table
    settings = get_settings()
    if not settings.api_keys and not settings.turso_enabled:
        logging.getLogger("classifinder").warning(
            "No API keys configured: every authenticated request will return 401. "
            "Set CLASSIFINDER_API_KEYS to a comma-separated list of keys."
        )
    init_db()
    init_feedback_table()
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Lightweight, stateless API that scans text for leaked secrets and credentials. "
            "Returns structured JSON with type, confidence, severity, span locations, "
            "and optionally redacted text. Built for AI agents, LLM pipelines, and CI/CD."
        ),
        docs_url="/docs",
        openapi_url="/v1/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────────
    # Allow all origins — agents call from everywhere.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ── Custom middleware ────────────────────────────────────────────────────
    # Starlette inserts each middleware at index 0, so the LAST add_middleware
    # call becomes the outermost (first to execute). Desired execution order:
    #   attach_request_id → AuthMiddleware → RateLimitMiddleware → LoggingMiddleware → route
    # So we add in reverse: Logging first, then RateLimit, then Auth (outermost).
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthMiddleware)

    # ── Request ID injection ─────────────────────────────────────────────────
    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):
        """Attach a unique request_id to every request before routing."""
        # Routes may overwrite this with their own req_ ID after they run;
        # this ensures the field always exists for the logging middleware.
        request.state.request_id = f"req_{uuid.uuid4().hex[:12]}"
        request.state.finding_count = None
        request.state.api_key_hash = None
        return await call_next(request)

    # ── Exception handlers ───────────────────────────────────────────────────

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "invalid_request",
                    "message": str(exc.errors()[0]["msg"]) if exc.errors() else "Invalid request.",
                    "retry_after": None,
                }
            },
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "not_found",
                    "message": f"No route found for {request.method} {request.url.path}",
                    "retry_after": None,
                }
            },
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc):
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred. Contact support if the issue persists.",
                    "retry_after": None,
                }
            },
        )

    # HTTPException raised inside routes (e.g., payload_too_large)
    from fastapi import HTTPException

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if isinstance(exc.detail, dict):
            error = exc.detail
        else:
            error = {"code": "invalid_request", "message": str(exc.detail)}
        error.setdefault("retry_after", None)  # type: ignore[arg-type]
        return JSONResponse(status_code=exc.status_code, content={"error": error})

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(types.router)
    app.include_router(scan.router)
    app.include_router(redact.router)
    app.include_router(feedback.router)
    app.include_router(keys.router)
    app.include_router(demo.router)

    return app


app = create_app()
