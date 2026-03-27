"""
ClassiFinder — POST /v1/redact

Scans text and returns a sanitized version with all detected secrets replaced.
The redacted_text field is safe to forward to an LLM or store in logs.
"""

import time
import uuid
from fastapi import APIRouter, Request, HTTPException

from app.config import get_settings
from app.engine.scanner import scan
from app.engine.redactor import redact
from app.models.requests import RedactRequest
from app.models.responses import RedactFindingResponse, RedactResponse, Span, SeveritySummary

router = APIRouter()


def _build_summary(findings) -> SeveritySummary:
    summary = SeveritySummary()
    for f in findings:
        if f.severity == "critical":
            summary.critical += 1
        elif f.severity == "high":
            summary.high += 1
        elif f.severity == "medium":
            summary.medium += 1
        elif f.severity == "low":
            summary.low += 1
    return summary


@router.post(
    "/v1/redact",
    response_model=RedactResponse,
    summary="Scan and redact secrets from text",
    description=(
        "Scans text for secrets and returns a sanitized copy with all detected secrets replaced. "
        "Use this as LLM preprocessing middleware to prevent secrets from reaching model context. "
        "The redacted_text field is safe to forward to any downstream system."
    ),
)
async def redact_text(request: Request, body: RedactRequest) -> RedactResponse:
    """Scan text, redact findings, return safe version."""
    settings = get_settings()

    # Payload size check
    text_bytes = len(body.text.encode("utf-8"))
    if text_bytes > settings.max_payload_bytes:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "payload_too_large",
                "message": (
                    f"Text size {text_bytes} bytes exceeds the limit of "
                    f"{settings.max_payload_bytes} bytes for your tier."
                ),
            },
        )

    request_id = f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id

    t0 = time.monotonic()
    findings = scan(
        text=body.text,
        types=body.types,
        min_confidence=body.min_confidence,
        include_context=False,  # Context not needed/returned in redact responses
    )
    redacted_text, redaction_map = redact(body.text, findings, style=body.redaction_style)
    scan_time_ms = int((time.monotonic() - t0) * 1000)

    request.state.finding_count = len(findings)

    # Build a lookup from finding_id → redacted_as
    redacted_as_map = {entry["finding_id"]: entry["redacted_as"] for entry in redaction_map}

    finding_responses = [
        RedactFindingResponse(
            id=f.id,
            type=f.type,
            severity=f.severity,
            confidence=f.confidence,
            span=Span(start=f.span_start, end=f.span_end),
            redacted_as=redacted_as_map.get(f.id, ""),
        )
        for f in findings
    ]

    return RedactResponse(
        request_id=request_id,
        scan_time_ms=scan_time_ms,
        findings_count=len(finding_responses),
        redacted_text=redacted_text,
        findings=finding_responses,
        summary=_build_summary(findings),
    )
