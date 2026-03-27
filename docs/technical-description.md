# ClassiFinder — Technical Description

## What It Is

ClassiFinder is a stateless REST API that scans arbitrary text for leaked secrets and credentials. It accepts raw text via HTTP, runs it against a library of 46 regex-based detection patterns, and returns structured JSON describing every secret found — including type classification, confidence scoring, severity levels, character-level span locations, and remediation guidance. It can also return a redacted copy of the input with all secrets replaced, making it suitable as preprocessing middleware for LLM pipelines.

There is no database, no user accounts, and no persistent state. Every request is independent: text in, findings out.

## Architecture

### Engine (`app/engine/`)

The core scanner is a pure function with no I/O and no side effects. It consists of:

- **`scanner.py`** — The `scan(text, types?, min_confidence?, include_context?) -> List[Finding]` function. Iterates all registered patterns against the input, calculates confidence via a multi-factor scoring algorithm (base confidence + context keyword boost + entropy analysis - test value penalty), deduplicates overlapping spans (highest confidence wins), and returns findings sorted by position. Benchmarks at ~4.7ms P50 for a 6.6KB document with 80 findings.

- **`redactor.py`** — The `redact(text, findings, style) -> (redacted_text, redaction_map)` function. Takes scanner output and replaces each secret in the original text. Processes spans in reverse order (highest offset first) so replacements don't shift earlier offsets. Supports three styles:
  - `label`: `[AWS_ACCESS_KEY_REDACTED]`
  - `mask`: `AKIA**************`
  - `hash`: `[REDACTED:sha256:a1b2c3d4]` (deterministic, for cross-scan deduplication)

- **`entropy.py`** — Shannon entropy calculator. Used by the confidence scorer to penalize low-entropy matches in generic patterns (e.g., a hex string that looks random vs. one that's all zeros).

- **`patterns/`** — 46 detection rules across 6 modules (`cloud`, `payment`, `vcs`, `comms`, `database`, `generic`). Each pattern is a `SecretPattern` dataclass containing a compiled regex with named capture groups, base confidence, entropy threshold, context keywords, known test values, severity level, and remediation text. All patterns register into a global `PATTERN_REGISTRY` list at import time.

### API Layer (`app/`)

A FastAPI application that wraps the engine:

- **`main.py`** — Application factory. Configures CORS (allow all origins), wires middleware in correct execution order (request ID injection → auth → rate limiting → logging → route), registers exception handlers that normalize all errors to `{"error": {"code": "...", "message": "..."}}` format, and mounts all routers.

- **`config.py`** — Loads settings from environment variables: `CLASSIFINDER_API_KEYS` (comma-separated valid keys), `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` (default 60), `CLASSIFINDER_MAX_PAYLOAD_BYTES` (default 256KB), `CLASSIFINDER_VERSION`. Singleton via `@lru_cache`.

- **`models/requests.py`** — Pydantic v2 request models with validation: `ScanRequest`, `RedactRequest`, `FeedbackRequest`. Includes field constraints (`min_confidence` clamped 0.0–1.0, `redaction_style` enum validation).

- **`models/responses.py`** — Response models mapping engine dataclasses to API JSON shapes. `FindingResponse.from_engine()` converts the engine's `Finding` dataclass (which uses flat `span_start`/`span_end` fields) into the API's nested `span: {start, end}` structure.

### Middleware (`app/middleware/`)

Three middleware layers, executed in this order on every request:

1. **`auth.py`** — Validates `X-API-Key` header against the configured key list. Exempt: `GET /v1/health`. Attaches `api_key_hash` (first 8 chars of SHA-256) and `is_test_key` flag to `request.state`. Returns 401 with structured error for invalid keys.

2. **`rate_limit.py`** — In-memory sliding window rate limiter keyed by `api_key_hash`. Maintains a `dict[str, list[float]]` of timestamps per key, pruning entries older than 60 seconds on each check. Adds `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers to every response. Returns 429 with `Retry-After` header when exceeded. Not suitable for multi-process deployments (no shared state).

3. **`logging.py`** — Emits one JSON log line per request to stdout. Fields: `request_id`, `api_key_hash`, `timestamp`, `method`, `endpoint`, `input_size_bytes`, `finding_count`, `response_time_ms`, `status_code`. **Never logs request bodies or secret values.**

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/scan` | Required | Scan text, return structured findings |
| `POST` | `/v1/redact` | Required | Scan text, return redacted copy + findings |
| `GET` | `/v1/types` | Required | List all 46 detection patterns with metadata |
| `GET` | `/v1/health` | Exempt | Service status, version, pattern count, uptime |
| `POST` | `/v1/feedback` | Required | Report false positives/negatives (202 Accepted, logged to stdout) |

### Security Constraints

- **No full secret values in responses.** `value_preview` shows first 4 + last 4 characters only.
- **No request bodies in logs.** Only metadata (size, finding count, timing).
- **No secret values in logs.** Feedback endpoint logs `has_comment: true/false`, never the comment text.
- **API key never stored in request state.** Only the first 8 chars of its SHA-256 hash.

## Confidence Scoring Algorithm

```
confidence = pattern.confidence_base
           + context_keyword_boost   (up to +0.10, in +0.02 increments per keyword within 50 chars)
           - entropy_penalty         (-0.30 if entropy < threshold, generic patterns only)
           → override to 0.15       (if value matches a known test credential)
           → clamp to [0.05, 0.99]
```

## Tech Stack

- Python 3.12+, FastAPI, Uvicorn, Pydantic v2
- No database, no Redis, no external services
- Test suite: pytest + FastAPI TestClient (57 tests: 21 pattern tests + 36 API integration tests)

## Running

```bash
# Install
pip install -r requirements.txt

# Run
CLASSIFINDER_API_KEYS=ss_live_yourkey uvicorn app.main:app --reload --port 8000

# Test
python -m pytest tests/ -v

# Docker
docker build -t classifinder . && docker run -e CLASSIFINDER_API_KEYS=ss_live_yourkey -p 8000:8000 classifinder
```

Swagger UI at `http://localhost:8000/docs`, OpenAPI spec at `/v1/openapi.json`.
