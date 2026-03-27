"""
ClassiFinder — Request Models

Pydantic v2 models for all API request bodies.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, model_validator


class ScanRequest(BaseModel):
    """Request body for POST /v1/scan."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "types": ["all"],
                "min_confidence": 0.5,
                "include_context": True,
            }
        }
    }

    text: str = Field(..., description="The text to scan. Max size depends on tier.")
    types: List[str] = Field(
        default=["all"],
        description="Secret types to detect. Use GET /v1/types for the full list. Default: all.",
    )
    min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold (0.0–1.0). Findings below this are excluded.",
    )
    include_context: bool = Field(
        default=True,
        description="If true, include a short text snippet around each finding for human review.",
    )


class RedactRequest(BaseModel):
    """Request body for POST /v1/redact."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgres://admin:secret@db:5432/prod",
                "types": ["all"],
                "min_confidence": 0.5,
                "redaction_style": "label",
            }
        }
    }

    text: str = Field(..., description="The text to redact.")
    types: List[str] = Field(
        default=["all"],
        description="Secret types to detect and redact. Default: all.",
    )
    min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to trigger redaction.",
    )
    redaction_style: str = Field(
        default="label",
        description=(
            'How to replace secrets: "label" → [AWS_KEY_REDACTED], '
            '"mask" → AKIA**************, '
            '"hash" → [REDACTED:sha256:a1b2c3] (for deduplication).'
        ),
    )

    @model_validator(mode="after")
    def validate_redaction_style(self) -> "RedactRequest":
        valid = {"label", "mask", "hash"}
        if self.redaction_style not in valid:
            raise ValueError(f"redaction_style must be one of: {', '.join(sorted(valid))}")
        return self


class FeedbackRequest(BaseModel):
    """Request body for POST /v1/feedback."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "request_id": "req_a1b2c3d4e5f6",
                "finding_id": "f_001",
                "feedback_type": "false_negative",
                "expected_type": "aws_access_key",
                "comment": "This is definitely an AWS key, scanner missed it.",
            }
        }
    }

    request_id: str = Field(..., description="The original request ID.")
    finding_id: str = Field(..., description="The specific finding being reported.")
    feedback_type: str = Field(
        ..., description='"false_positive" or "false_negative".'
    )
    expected_type: Optional[str] = Field(
        default=None,
        description=(
            "For false negatives: the secret type you expected to be detected. "
            "Must be a valid type ID from GET /v1/types."
        ),
    )
    comment: Optional[str] = Field(default=None, description="Optional context.")

    @model_validator(mode="after")
    def validate_feedback_fields(self) -> "FeedbackRequest":
        valid_types = {"false_positive", "false_negative"}
        if self.feedback_type not in valid_types:
            raise ValueError(f"feedback_type must be one of: {', '.join(sorted(valid_types))}")

        if self.expected_type is not None:
            from app.engine.patterns.registry import PATTERN_REGISTRY
            valid_pattern_ids = {p.id for p in PATTERN_REGISTRY}
            if self.expected_type not in valid_pattern_ids:
                raise ValueError(
                    f"expected_type '{self.expected_type}' is not a recognized pattern type. "
                    f"Use GET /v1/types for valid IDs."
                )
        return self


class KeyCreateRequest(BaseModel):
    """Request body for POST /v1/keys/create."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "developer@example.com",
                "subscribe": True,
            }
        }
    }

    email: str = Field(..., description="Email address to associate with the API key.")
    subscribe: bool = Field(
        default=False,
        description="Opt in to product updates and new feature announcements.",
    )

    @model_validator(mode="after")
    def validate_and_normalize_email(self) -> "KeyCreateRequest":
        email = self.email.strip().lower()
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError("Invalid email address.")
        self.email = email
        return self
