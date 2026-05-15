"""
ClassiFinder — Response Models

Pydantic v2 models for all API responses. These map from engine dataclasses
to the JSON shapes defined in classifinder-api-spec.md.
"""

from typing import List, Optional
from pydantic import BaseModel, Field

from app.engine.scanner import Finding as EngineFinding


# ── Shared sub-models ────────────────────────────────────────────────────────


class Span(BaseModel):
    """Character offset range (start inclusive, end exclusive)."""

    start: int = Field(..., description="Start character offset (inclusive).")
    end: int = Field(..., description="End character offset (exclusive).")


class SeveritySummary(BaseModel):
    """Count of findings per severity level."""

    critical: int = Field(default=0)
    high: int = Field(default=0)
    medium: int = Field(default=0)
    low: int = Field(default=0)


# ── Finding response models ───────────────────────────────────────────────────


class FindingResponse(BaseModel):
    """A single detected secret, as returned by /v1/scan."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "f_001",
                "type": "aws_access_key",
                "type_name": "AWS Access Key ID",
                "provider": "aws",
                "severity": "critical",
                "confidence": 0.98,
                "value_preview": "AKIA****MPLE",
                "span": {"start": 22, "end": 42},
                "context": "...AWS_ACCESS_KEY_ID=AKIA****MPLE\nAWS_SECRET...",
                "is_likely_test_value": False,
                "recommendation": "Rotate this key immediately in the AWS IAM console.",
                "matched_pattern": "aws_access_key_v1",
                "safe_mcp_ids": [],
            }
        }
    }

    id: str = Field(..., description="Unique finding ID within this response.")
    type: str = Field(..., description="Machine-readable secret type identifier.")
    type_name: str = Field(..., description="Human-readable secret type name.")
    provider: str = Field(..., description='Service provider (aws, stripe, github, etc.) or "generic".')
    severity: str = Field(..., description="critical / high / medium / low.")
    confidence: float = Field(..., description="Detection confidence from 0.0 to 1.0.")
    value_preview: str = Field(
        ..., description="Partially masked value showing prefix/suffix only. Never the full secret."
    )
    span: Span = Field(..., description="Character offsets in the original text.")
    context: Optional[str] = Field(
        default=None,
        description="Short snippet around the finding with the secret masked. Present when include_context=true.",
    )
    is_likely_test_value: bool = Field(
        ..., description="True if the value matches known test/example credentials."
    )
    recommendation: str = Field(..., description="Actionable remediation guidance.")
    matched_pattern: str = Field(
        ..., description="Internal pattern ID that triggered (useful for reporting false positives)."
    )
    safe_mcp_ids: List[str] = Field(
        default_factory=list,
        description=(
            "SAFE-MCP technique IDs this finding maps to (e.g., 'SAFE-T1001', 'SAFE-T1102'). "
            "Populated for prompt-injection findings; empty for secret findings. "
            "See https://github.com/safe-mcp/safe-mcp for the technique catalog."
        ),
    )

    @classmethod
    def from_engine(cls, f: EngineFinding) -> "FindingResponse":
        """Convert an engine Finding dataclass to a FindingResponse."""
        return cls(
            id=f.id,
            type=f.type,
            type_name=f.type_name,
            provider=f.provider,
            severity=f.severity,
            confidence=f.confidence,
            value_preview=f.value_preview,
            span=Span(start=f.span_start, end=f.span_end),
            context=f.context,
            is_likely_test_value=f.is_likely_test_value,
            recommendation=f.recommendation,
            matched_pattern=f.matched_pattern,
            safe_mcp_ids=list(f.safe_mcp_ids),
        )


class RedactFindingResponse(BaseModel):
    """Slim finding as returned by /v1/redact — no context, adds redacted_as."""

    id: str = Field(..., description="Unique finding ID within this response.")
    type: str = Field(..., description="Machine-readable secret type identifier.")
    severity: str = Field(..., description="critical / high / medium / low.")
    confidence: float = Field(..., description="Detection confidence from 0.0 to 1.0.")
    span: Span = Field(..., description="Character offsets in the original text.")
    redacted_as: str = Field(..., description="The replacement string used in redacted_text.")


# ── Endpoint response models ──────────────────────────────────────────────────


class ScanResponse(BaseModel):
    """Response body for POST /v1/scan."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "request_id": "req_a1b2c3d4e5f6",
                "scan_time_ms": 7,
                "findings_count": 1,
                "findings": [
                    {
                        "id": "f_001",
                        "type": "aws_access_key",
                        "type_name": "AWS Access Key ID",
                        "provider": "aws",
                        "severity": "critical",
                        "confidence": 0.98,
                        "value_preview": "AKIA****MPLE",
                        "span": {"start": 22, "end": 42},
                        "context": "...AWS_ACCESS_KEY_ID=AKIA****MPLE...",
                        "is_likely_test_value": False,
                        "recommendation": "Rotate this key immediately.",
                        "matched_pattern": "aws_access_key_v1",
                    }
                ],
                "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            }
        }
    }

    request_id: str
    scan_time_ms: int
    findings_count: int
    findings: List[FindingResponse]
    summary: SeveritySummary


class RedactResponse(BaseModel):
    """Response body for POST /v1/redact."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "request_id": "req_x9y8z7w6v5u4",
                "scan_time_ms": 8,
                "findings_count": 1,
                "redacted_text": "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]",
                "findings": [
                    {
                        "id": "f_001",
                        "type": "aws_access_key",
                        "severity": "critical",
                        "confidence": 0.98,
                        "span": {"start": 22, "end": 42},
                        "redacted_as": "[AWS_ACCESS_KEY_REDACTED]",
                    }
                ],
                "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            }
        }
    }

    request_id: str
    scan_time_ms: int
    findings_count: int
    redacted_text: str
    findings: List[RedactFindingResponse]
    summary: SeveritySummary


class TypeInfo(BaseModel):
    """Metadata about a single supported secret type."""

    id: str = Field(..., description="Machine-readable type identifier.")
    name: str = Field(..., description="Human-readable type name.")
    provider: str = Field(..., description="Service provider.")
    severity: str = Field(..., description="critical / high / medium / low.")
    description: str = Field(..., description="What this secret type is.")
    tags: List[str] = Field(default_factory=list, description="Searchable tags.")


class TypesResponse(BaseModel):
    """Response body for GET /v1/types."""

    types_count: int
    types: List[TypeInfo]


class HealthResponse(BaseModel):
    """Response body for GET /v1/health."""

    status: str = Field(default="healthy")
    version: str
    patterns_loaded: int
    uptime_seconds: int


class FeedbackResponse(BaseModel):
    """Response body for POST /v1/feedback (202 Accepted)."""

    feedback_id: str
    status: str = Field(default="received")


# ── Error models ──────────────────────────────────────────────────────────────


class ErrorDetail(BaseModel):
    """Inner error object."""

    code: str
    message: str
    retry_after: Optional[int] = Field(
        default=None, description="Seconds to wait before retrying (rate limit errors only)."
    )


class ErrorResponse(BaseModel):
    """Standard error response envelope."""

    error: ErrorDetail


class KeyCreateResponse(BaseModel):
    """Response body for POST /v1/keys/create and /v1/keys/rotate."""

    api_key: str = Field(..., description="The generated API key. Save it — you will not see it again.")
    email: str = Field(..., description="The email associated with this key.")
    created_at: str = Field(..., description="ISO 8601 timestamp.")
    message: str = Field(default="Save this key — you will not see it again.")
