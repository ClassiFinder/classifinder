# ClassiFinder — FastAPI Wrapper Implementation Plan

## What This Document Is

This is a context briefing for implementing the FastAPI API layer around the ClassiFinder scanner engine. Read this first, then read the project files referenced below before writing any code.

---

## Project State

The core scanner engine is built and tested. It lives in `app/engine/` and consists of:

- **`app/engine/scanner.py`** — The main `scan()` function. Pure function: takes text, returns a list of `Finding` dataclasses. No I/O, no side effects. This is the heart of the product.
- **`app/engine/redactor.py`** — The `redact()` function. Takes text + findings from the scanner, returns `(redacted_text, redaction_map)`. Supports three styles: `label`, `mask`, `hash`.
- **`app/engine/entropy.py`** — Shannon entropy calculator used by the confidence scorer.
- **`app/engine/patterns/`** — Pattern library with 46 secret detection rules across 6 modules: `cloud.py`, `payment.py`, `vcs.py`, `comms.py`, `database.py`, `generic.py`. Each module registers patterns into a global `PATTERN_REGISTRY` via `registry.py`.
- **`tests/test_patterns.py`** — 21 tests, all passing. Covers true positives, true negatives, test value flagging, redaction, multi-secret scanning, and clean-text-no-findings.

The engine benchmarks at ~4.7ms P50 scanning a 6.6KB document with 80 findings. Well under our 50ms latency target.

---

## What Needs to Be Built

A FastAPI application that wraps the engine and exposes the API defined in `classifinder-api-spec.md`. Read that file carefully — it has the full endpoint definitions, request/response schemas, error format, and rate limit structure.

### Endpoints to Implement

1. **`POST /v1/scan`** — Accepts `{text, types?, min_confidence?, include_context?}`, calls `scanner.scan()`, returns structured JSON with findings and summary.

2. **`POST /v1/redact`** — Accepts `{text, types?, min_confidence?, redaction_style?}`, calls `scanner.scan()` then `redactor.redact()`, returns redacted text + findings.

3. **`GET /v1/types`** — Returns the list of all registered patterns with metadata (id, name, provider, severity, description, tags). Read from `PATTERN_REGISTRY`.

4. **`GET /v1/health`** — Returns service status, version, pattern count, uptime.

5. **`POST /v1/feedback`** — Accepts false positive/negative reports. For MVP, just validate the input and return 202 Accepted. We don't need a database backend for this yet — log the feedback metadata to stdout (never the original text).

### Pydantic Models

Create request and response models in `app/models/`. The API spec has exact field names, types, and defaults. Key models:

- `ScanRequest` / `ScanResponse`
- `RedactRequest` / `RedactResponse`
- `Finding` (response model — maps from the engine's `Finding` dataclass)
- `TypeInfo` / `TypesResponse`
- `HealthResponse`
- `FeedbackRequest` / `FeedbackResponse`
- `ErrorResponse`

### Middleware

- **API key validation** — Check `X-API-Key` header on every request except `/v1/health`. For MVP, validate against a list of keys from environment variables (e.g., `SECRETSWEEP_API_KEYS=ss_live_key1,ss_live_key2`). Keys with `ss_test_` prefix should work but not count toward billing. Return 401 for missing/invalid keys.

- **Rate limiting** — For MVP, use an in-memory sliding window per API key. Limits per the spec: Free tier = 60 req/min. Don't over-engineer this — a simple dict of `{key_hash: [timestamps]}` works. Return 429 with `Retry-After` header when exceeded.

- **Request size validation** — Check `Content-Length` against tier limits (256KB for free). Return 400 `payload_too_large` if exceeded.

- **CORS** — Allow all origins for now (agents call from everywhere).

- **Request ID generation** — Generate a `req_` prefixed UUID for every request. Include in response and logs.

### Logging

Follow the security architecture in `classifinder-architecture.md`:
- **NEVER log request bodies.** Users are sending us their secrets.
- **NEVER log finding values.** Only log finding counts.
- Log only: request_id, api_key_hash (first 8 chars of SHA-256), timestamp, endpoint, input_size_bytes, finding_count, response_time_ms, status_code.

### OpenAPI

FastAPI generates OpenAPI docs automatically. Make sure:
- The generated spec matches our API spec document
- Include realistic examples in the Pydantic models (FastAPI uses these for Swagger UI)
- Set title="ClassiFinder API", version="1.0.0", description with a short product summary
- The spec should be served at `/v1/openapi.json`
- Swagger UI at `/docs`

---

## File Structure Target

```
classifinder/
├── app/
│   ├── main.py                 # FastAPI app, lifespan, CORS, exception handlers
│   ├── routes/
│   │   ├── scan.py             # POST /v1/scan
│   │   ├── redact.py           # POST /v1/redact
│   │   ├── types.py            # GET /v1/types
│   │   ├── health.py           # GET /v1/health
│   │   └── feedback.py         # POST /v1/feedback
│   ├── engine/                 # ← Already built, don't modify
│   │   ├── scanner.py
│   │   ├── redactor.py
│   │   ├── entropy.py
│   │   └── patterns/
│   │       ├── registry.py
│   │       ├── cloud.py
│   │       ├── payment.py
│   │       ├── vcs.py
│   │       ├── comms.py
│   │       ├── database.py
│   │       └── generic.py
│   ├── models/
│   │   ├── requests.py         # Pydantic request models
│   │   └── responses.py        # Pydantic response models
│   ├── middleware/
│   │   ├── auth.py             # API key validation
│   │   ├── rate_limit.py       # In-memory rate limiter
│   │   └── logging.py          # Request metadata logger
│   └── config.py               # Settings from env vars
├── tests/
│   ├── test_patterns.py        # ← Already built, don't modify
│   └── test_api.py             # New: integration tests for API endpoints
├── Dockerfile
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Design Decisions Already Made

- **Framework**: FastAPI + Uvicorn. Pydantic v2 for models.
- **Auth**: API key in `X-API-Key` header. Key format: `ss_live_` or `ss_test_` prefix, 48 chars total.
- **Rate limits**: In-memory for MVP. Redis later if needed.
- **No database**: The API is stateless. No request storage. Feedback endpoint logs to stdout for now.
- **Response format**: All responses follow the schemas in the API spec. Errors use `{"error": {"code": "...", "message": "...", "retry_after": ...}}`.

---

## Key Reference Files

Read these before starting implementation:

1. **`classifinder-api-spec.md`** — Complete API specification with request/response schemas, field descriptions, and example payloads. This is the source of truth for what the API should look like.

2. **`classifinder-architecture.md`** — Technical architecture including security rules (what to log/not log), confidence scoring algorithm, and system design.

3. **`app/engine/scanner.py`** — The scan function signature and the Finding dataclass. Your route handlers will call this directly.

4. **`app/engine/redactor.py`** — The redact function signature. Takes text + findings + style, returns (redacted_text, redaction_map).

5. **`app/engine/patterns/registry.py`** — The `PATTERN_REGISTRY` list and `SecretPattern` dataclass. The `/v1/types` endpoint reads from this.

---

## What Not to Do

- Don't modify anything in `app/engine/`. The scanner is tested and working.
- Don't add a database. The MVP is stateless.
- Don't add user accounts or registration. API keys only.
- Don't add dashboards or web UI. This is an API product.
- Don't over-engineer rate limiting. A simple in-memory approach is fine for launch.
- Don't log request bodies or secret values under any circumstances.
