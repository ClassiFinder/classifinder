# Feedback Endpoint Build — Agent Bootstrap

## Context

ClassiFinder has a feedback endpoint (`POST /v1/feedback`) that currently accepts false positive/false negative reports but discards them — metadata is logged to stdout only, with no persistence or aggregation. We want to make this endpoint actually useful.

### Current State

- **Route:** `app/routes/feedback.py` — validates input, generates `fb_` ID, logs metadata to stdout, returns 202
- **Request model:** `app/models/requests.py` — `FeedbackRequest` with `request_id`, `finding_id`, `feedback_type` ("false_positive" | "false_negative"), optional `comment`
- **Response model:** `app/models/responses.py` — `FeedbackResponse` with `feedback_id`, `status`
- **Tests:** `tests/test_api.py` (5 tests covering auth, validation, responses)
- **No persistence layer** — feedback is printed to stdout and lost

### Core Constraint — DO NOT VIOLATE

ClassiFinder's security claim is **"we never store what you scan."** This means:
- **Never persist the matched secret string.** Users can't send us the false positive string itself.
- **Never persist the `comment` field as-is** — users could paste secrets into it.
- Storing structured metadata (IDs, types, timestamps, counts) is fine.
- Read `CLAUDE.md` at the repo root and `classifinder/CLAUDE.md` for full security rules before making any changes.

## What to Build

### 1. Persist Feedback to Turso

The project already has optional Turso integration for API key provisioning (`app/key_store.py`, `app/config.py`). Extend this to store feedback.

Schema suggestion:
```sql
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    feedback_type TEXT NOT NULL,  -- "false_positive" or "false_negative"
    has_comment BOOLEAN DEFAULT FALSE,
    api_key_hash TEXT,            -- SHA-256 prefix from auth middleware
    created_at TEXT NOT NULL      -- ISO 8601 timestamp
);
```

**Do not store the `comment` text.** Store only `has_comment` as a boolean flag.

Wire this into the existing feedback route handler. Keep it optional — if Turso isn't configured, fall back to stdout logging (current behavior).

### 2. Add a Secret Type Field for False Negatives

For false negatives ("you missed something"), users currently can only say "you missed a finding" with no structured way to say *what type* they expected. Add an optional `expected_type` field to `FeedbackRequest`:

```python
expected_type: Optional[str] = None  # e.g., "aws_access_key", "openai_api_key"
```

Validate it against the known pattern types from the engine's registry (same list returned by `GET /v1/types`). This makes false negative reports actionable without requiring the secret string. Persist this field in the feedback table.

### 3. Aggregate Signal Queries

Build a lightweight internal utility (not a public endpoint) that can query feedback trends:

- **False positive rate by pattern:** Which `finding_id` patterns get the most false positive reports?
- **False negative gaps:** Which `expected_type` values appear most in false negative reports?
- **Volume over time:** Feedback trend by day/week

This could be a CLI script (`scripts/feedback_report.py`) or a protected admin endpoint — implementer's choice. The point is making the data queryable so we can prioritize pattern improvements.

### 4. Update Tests

Add tests for:
- Feedback persisted to Turso when configured
- Fallback to stdout when Turso isn't configured
- `expected_type` validation (valid type accepted, unknown type rejected or accepted with warning)
- The aggregate query utility

### 5. Update API Spec

Update `classifinder/docs/classifinder-api-spec.md` with the new `expected_type` field and any response changes.

## Build Order Suggestion

1. Turso feedback table + persistence in route handler (with fallback)
2. `expected_type` field on request model + validation
3. Tests for persistence and new field
4. Aggregate query script/endpoint
5. API spec update

## Files You'll Touch

- `app/routes/feedback.py` — main handler changes
- `app/models/requests.py` — add `expected_type` field
- `app/config.py` or `app/key_store.py` — Turso table creation for feedback
- `tests/test_api.py` — new test cases
- `docs/classifinder-api-spec.md` — spec update
- New: `scripts/feedback_report.py` or `app/routes/admin.py` (aggregate queries)
