"""
ClassiFinder — POST /v1/feedback

Accept false positive / false negative reports. Persists structured metadata
to Turso when configured; falls back to stdout logging when Turso is unavailable.
Never stores comment text or secret values.
"""

import asyncio
import json
import sys
import time
import uuid
from collections import defaultdict
from typing import Dict, List

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.models.requests import FeedbackRequest
from app.models.responses import FeedbackResponse

router = APIRouter()

# ── Feedback-specific rate limit ─────────────────────────────────────────────
# Separate from the global rate limiter. Prevents abuse of the feedback endpoint
# without storing any user identity in the feedback records themselves.
# Keyed by api_key_hash (ephemeral, in-memory only — never persisted).

FEEDBACK_LIMIT_PER_HOUR = 10
FEEDBACK_WINDOW_SECONDS = 3600
_feedback_log: Dict[str, List[float]] = defaultdict(list)


def _check_feedback_rate_limit(key_hash: str) -> int | None:
    """Check if the key has exceeded the feedback rate limit.

    Returns None if under limit, or seconds until retry if over limit.
    """
    now = time.monotonic()
    cutoff = now - FEEDBACK_WINDOW_SECONDS
    timestamps = _feedback_log[key_hash]
    _feedback_log[key_hash] = [t for t in timestamps if t > cutoff]

    if len(_feedback_log[key_hash]) >= FEEDBACK_LIMIT_PER_HOUR:
        retry_after = int(FEEDBACK_WINDOW_SECONDS - (now - _feedback_log[key_hash][0]))
        return max(1, retry_after)

    _feedback_log[key_hash].append(now)
    return None


def reset_feedback_rate_limit() -> None:
    """Clear the feedback rate limit state. Used in tests."""
    _feedback_log.clear()

_feedback_conn = None


def _get_feedback_conn():
    """Get or create a Turso connection for feedback persistence."""
    global _feedback_conn
    if _feedback_conn is not None:
        return _feedback_conn
    settings = get_settings()
    if not settings.turso_enabled:
        raise RuntimeError("Turso is not configured")
    import libsql_experimental as libsql
    _feedback_conn = libsql.connect(
        settings.turso_database_url,
        auth_token=settings.turso_auth_token,
    )
    return _feedback_conn


def reset_feedback_conn() -> None:
    """Reset the connection. Used in tests."""
    global _feedback_conn
    _feedback_conn = None


def _persist_to_turso(
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    expected_type: str | None,
) -> None:
    """Insert anonymous feedback row into Turso. Synchronous — call via to_thread."""
    conn = _get_feedback_conn()
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn.execute(
        """INSERT INTO feedback
           (feedback_id, request_id, finding_id, feedback_type, has_comment, expected_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (feedback_id, request_id, finding_id, feedback_type, int(has_comment), expected_type, created_at),
    )
    conn.commit()


def _log_to_stdout(
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    expected_type: str | None,
) -> None:
    """Log feedback metadata to stdout (fallback when Turso is unavailable)."""
    log_entry = {
        "event": "feedback_received",
        "feedback_id": feedback_id,
        "request_id": request_id,
        "finding_id": finding_id,
        "feedback_type": feedback_type,
        "has_comment": has_comment,
        "expected_type": expected_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    print(json.dumps(log_entry), file=sys.stdout, flush=True)


@router.post(
    "/v1/feedback",
    response_model=FeedbackResponse,
    status_code=202,
    summary="Report a false positive or false negative",
    description=(
        "Submit feedback on a specific finding from a previous scan. "
        "Only finding metadata is stored — never the original text or secret value. "
        "For false negatives, include expected_type to indicate which pattern you expected. "
        "Returns 202 Accepted immediately."
    ),
)
async def submit_feedback(request: Request, body: FeedbackRequest) -> FeedbackResponse:
    """Validate and persist feedback. Never store or echo the original secret."""
    # Feedback-specific rate limit (in-memory, anonymous — no identity persisted)
    key_hash = getattr(request.state, "api_key_hash", None)
    if key_hash:
        retry_after = _check_feedback_rate_limit(key_hash)
        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "error": {
                        "code": "feedback_rate_limit_exceeded",
                        "message": f"Feedback is limited to {FEEDBACK_LIMIT_PER_HOUR} submissions per hour.",
                        "retry_after": retry_after,
                    }
                },
            )

    feedback_id = f"fb_{uuid.uuid4().hex[:6]}"
    settings = get_settings()

    has_comment = body.comment is not None

    if settings.turso_enabled:
        try:
            await asyncio.to_thread(
                _persist_to_turso,
                feedback_id=feedback_id,
                request_id=body.request_id,
                finding_id=body.finding_id,
                feedback_type=body.feedback_type,
                has_comment=has_comment,
                expected_type=body.expected_type,
            )
        except Exception:
            # Turso write failed — fall back to stdout
            _log_to_stdout(
                feedback_id=feedback_id,
                request_id=body.request_id,
                finding_id=body.finding_id,
                feedback_type=body.feedback_type,
                has_comment=has_comment,
                expected_type=body.expected_type,
            )
    else:
        _log_to_stdout(
            feedback_id=feedback_id,
            request_id=body.request_id,
            finding_id=body.finding_id,
            feedback_type=body.feedback_type,
            has_comment=has_comment,
            expected_type=body.expected_type,
        )

    return FeedbackResponse(feedback_id=feedback_id, status="received")
