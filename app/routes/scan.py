"""
ClassiFinder — POST /v1/scan

Scans text for secrets and returns structured findings. Does not modify input.
"""

import time
import uuid
from fastapi import APIRouter, Request, HTTPException

from app.config import get_settings
from app.engine.scanner import scan
from app.models.requests import ScanRequest
from app.models.responses import FindingResponse, ScanResponse, SeveritySummary

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
    "/v1/scan",
    response_model=ScanResponse,
    summary="Scan text for secrets",
    description=(
        "Scans the provided text for leaked secrets and credentials. "
        "Returns structured findings with type, confidence, severity, span, and remediation guidance. "
        "Never returns the full secret value — only a masked preview."
    ),
)
async def scan_text(request: Request, body: ScanRequest) -> ScanResponse:
    """Run the scanner and return structured findings."""
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
        include_context=body.include_context,
    )
    scan_time_ms = int((time.monotonic() - t0) * 1000)

    # Attach finding count for the logging middleware (never the values)
    request.state.finding_count = len(findings)

    finding_responses = [FindingResponse.from_engine(f) for f in findings]

    return ScanResponse(
        request_id=request_id,
        scan_time_ms=scan_time_ms,
        findings_count=len(finding_responses),
        findings=finding_responses,
        summary=_build_summary(findings),
    )
