# ClassiFinder — What Was Built

This document covers everything that has been implemented in the ClassiFinder project: the scanner engine, the FastAPI wrapper, middleware, tests, and deployment infrastructure.

---

## What ClassiFinder Is

ClassiFinder is a lightweight, stateless API that scans text for leaked secrets and credentials. It returns structured JSON with detection type, confidence, severity, character span locations, and optionally a redacted version of the input text.

It is built for two audiences:

- **AI agent builders** who need to strip secrets from user input before it enters an LLM context window (`/v1/redact`)
- **CI/CD pipelines** that need to detect credentials in code, configs, or logs before they ship (`/v1/scan`)

The API is stateless by design. Nothing is stored. Request bodies are never logged. Users are sending their secrets — the architecture treats that seriously.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12+ |
| Framework | FastAPI + Uvicorn |
| Models | Pydantic v2 |
| Tests | pytest + FastAPI TestClient |
| Container | Docker (python:3.12-slim) |
| Database | Turso (hosted SQLite) — optional, for key provisioning and anonymous feedback |

Dependencies are minimal: `fastapi`, `uvicorn[standard]`, `pydantic`, `httpx` (for TestClient), `libsql-experimental` (Turso), and `pytest`.

---

## Project Structure

```
classifinder/
├── app/
│   ├── main.py                  # FastAPI app, lifespan, CORS, exception handlers
│   ├── config.py                # Settings from environment variables
│   ├── key_store.py             # Turso-backed API key lifecycle (generate, lookup, rotate)
│   ├── feedback_store.py        # Anonymous feedback persistence + aggregate queries
│   ├── routes/
│   │   ├── scan.py              # POST /v1/scan
│   │   ├── redact.py            # POST /v1/redact
│   │   ├── types.py             # GET /v1/types
│   │   ├── health.py            # GET /v1/health
│   │   ├── feedback.py          # POST /v1/feedback (Turso + stdout fallback)
│   │   └── keys.py              # POST /v1/keys/create, POST /v1/keys/rotate
│   ├── engine/                  # Core scanner — pure functions, no I/O
│   │   ├── scanner.py           # scan() function + Finding dataclass
│   │   ├── redactor.py          # redact() function
│   │   ├── entropy.py           # Shannon entropy calculator
│   │   └── patterns/
│   │       ├── registry.py      # PATTERN_REGISTRY + SecretPattern dataclass
│   │       ├── cloud.py         # AWS, GCP, Azure, DigitalOcean, etc.
│   │       ├── payment.py       # Stripe, PayPal, Square
│   │       ├── vcs.py           # GitHub, GitLab, Bitbucket, CircleCI
│   │       ├── comms.py         # Slack, Twilio, SendGrid, Discord
│   │       ├── database.py      # Connection strings, SSH/PEM keys
│   │       ├── ai.py            # OpenAI, Anthropic, Cohere API keys
│   │       └── generic.py       # JWT, Bearer tokens, .env secrets, high-entropy strings
│   ├── models/
│   │   ├── requests.py          # ScanRequest, RedactRequest, FeedbackRequest
│   │   └── responses.py         # ScanResponse, RedactResponse, FindingResponse, etc.
│   └── middleware/
│       ├── auth.py              # API key validation
│       ├── rate_limit.py        # In-memory sliding window rate limiter
│       └── logging.py           # Safe metadata-only request logger
├── scripts/
│   └── feedback_report.py       # CLI tool for querying feedback trends
├── tests/
│   ├── test_patterns.py         # 21 pattern accuracy tests
│   ├── test_api.py              # 36 API integration tests
│   ├── test_feedback.py         # 15 feedback persistence + rate limit tests
│   └── test_keys.py             # 12 key provisioning tests
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── CLAUDE.md
├── FASTAPI-IMPLEMENTATION-PLAN.md
├── classifinder-api-spec.md
└── classifinder-architecture.md
```

---

## The Engine (`app/engine/`)

The engine is a pure function: text in, findings out. No I/O, no state, no side effects. It was built and tested first, before the API layer.

### Scanner (`app/engine/scanner.py`)

The `scan()` function is the core of the product. It:

1. Runs all registered patterns (or a filtered subset) against the input text
2. For each regex match, extracts the secret value via named capture groups
3. Calculates confidence using a multi-factor scoring algorithm
4. Deduplicates overlapping findings (keeps the highest-confidence match)
5. Returns findings sorted by position in the text

**Function signature:**

```python
def scan(
    text: str,
    types: Optional[List[str]] = None,    # Filter to specific pattern IDs
    min_confidence: float = 0.5,           # Exclude low-confidence findings
    include_context: bool = True,          # Include text snippets for review
) -> List[Finding]
```

**The Finding dataclass:**

```python
@dataclass
class Finding:
    id: str                    # "f_001", "f_002", etc.
    type: str                  # "aws_access_key"
    type_name: str             # "AWS Access Key ID"
    provider: str              # "aws"
    severity: str              # "critical" / "high" / "medium" / "low"
    confidence: float          # 0.05 to 0.99
    value_preview: str         # "AKIA****MPLE" (masked, never full value)
    span_start: int            # Character offset (inclusive)
    span_end: int              # Character offset (exclusive)
    context: Optional[str]     # "...AWS_ACCESS_KEY_ID=AKIA****MPLE\n..."
    is_likely_test_value: bool # True for known example credentials
    recommendation: str        # "Rotate this key immediately..."
    matched_pattern: str       # "aws_access_key_v1"
```

### Confidence Scoring

Confidence is calculated per finding:

```
confidence = base_confidence
           + context_boost       (+0.02 per nearby keyword, max +0.10)
           - low_entropy_penalty (up to -0.30 for generic patterns)
           - test_value_penalty  (drops to 0.15 for known test values)

Clamped to [0.05, 0.99]
```

- **Prefix-anchored patterns** (AKIA, sk_live_, ghp_) start at 0.95 base confidence
- **Structural patterns** (connection strings, PEM blocks) start at 0.90
- **Format-only patterns** (high-entropy strings) start at 0.60
- **Context keywords** like "key", "token", "secret", "password" within 50 characters boost confidence by +0.02 each

### Redactor (`app/engine/redactor.py`)

The `redact()` function takes scanner output and produces sanitized text. It processes findings from end-to-start so replacements don't shift character offsets.

Three redaction styles:

| Style | Example Output |
|-------|---------------|
| `label` | `[AWS_ACCESS_KEY_REDACTED]` |
| `mask` | `AKIA****************` |
| `hash` | `[REDACTED:sha256:a1b2c3d4]` |

The `hash` style is useful for deduplication — the same secret always produces the same hash token.

### Pattern Library (`app/engine/patterns/`)

71 detection patterns across 7 categories:

| Category | Module | Examples |
|----------|--------|----------|
| Cloud providers | `cloud.py` | AWS access/secret keys, GCP API keys, Azure storage keys, DigitalOcean tokens, Heroku, Cloudflare |
| Payment | `payment.py` | Stripe live/test keys, Stripe webhook secrets, PayPal, Square |
| Version control | `vcs.py` | GitHub PATs (classic + fine-grained), GitLab tokens, Bitbucket passwords, CircleCI, Jenkins |
| Communications | `comms.py` | Slack bot/user tokens, Slack webhooks, Twilio, SendGrid, Discord, Telegram |
| Database | `database.py` | PostgreSQL/MySQL/MongoDB/Redis connection strings, SSH private keys, PEM blocks |
| AI providers | `ai.py` | OpenAI, Anthropic, Cohere API keys |
| Generic | `generic.py` | JWTs, Bearer tokens, Basic Auth, .env API keys, high-entropy strings, passwords in URLs |

Each pattern is a `SecretPattern` dataclass with:
- A compiled regex with named capture groups (`?P<secret>`)
- Base confidence score
- Shannon entropy threshold (for generic patterns)
- Known test values (to flag AWS example keys, Stripe test keys, etc.)
- Context keywords that boost confidence
- Provider, severity, tags, and remediation guidance

### Entropy Calculator (`app/engine/entropy.py`)

Computes Shannon entropy to filter low-entropy false positives on generic patterns. A string like `AAAAAAAAAAAAA` matching a generic key pattern gets a heavy confidence penalty because its entropy is low.

### Performance

The engine benchmarks at ~4.7ms P50 scanning a 6.6KB document with 80 findings. Well under the 50ms latency target.

---

## The API Layer (`app/routes/`, `app/models/`, `app/middleware/`)

### Endpoints

#### `POST /v1/scan`

Scans text for secrets. Returns structured findings without modifying input.

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: ss_live_..." \
  -H "Content-Type: application/json" \
  -d '{"text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}'
```

Response includes `request_id`, `scan_time_ms`, `findings_count`, an array of `findings`, and a `summary` with counts per severity level. Full secret values are never returned — only masked previews like `AKIA****MPLE`.

Request parameters:
- `text` (required) — the text to scan
- `types` (optional, default `["all"]`) — filter to specific secret types
- `min_confidence` (optional, default `0.5`) — exclude low-confidence findings
- `include_context` (optional, default `true`) — include text snippets around findings

#### `POST /v1/redact`

Scans text and returns a sanitized version with secrets replaced. This is the primary endpoint for LLM preprocessing middleware.

```bash
curl -X POST http://localhost:8000/v1/redact \
  -H "X-API-Key: ss_live_..." \
  -d '{"text": "Deploy with AKIAIOSFODNN7EXAMPLE to prod"}'
```

The `redacted_text` field in the response is safe to forward to any LLM or downstream system.

Request parameters:
- `text` (required) — the text to redact
- `types` (optional, default `["all"]`) — filter to specific secret types
- `min_confidence` (optional, default `0.5`) — minimum confidence to trigger redaction
- `redaction_style` (optional, default `"label"`) — `"label"`, `"mask"`, or `"hash"`

Redact findings are slimmer than scan findings — they include `redacted_as` but exclude `context`, `value_preview`, `type_name`, and other fields that aren't needed when the goal is sanitization.

#### `GET /v1/types`

Returns metadata for all 71 registered detection patterns. Agents use this for self-discovery — to learn what the API detects and build type filter lists.

Response fields per type: `id`, `name`, `provider`, `severity`, `description`, `tags`.

#### `GET /v1/health`

Returns service status, version, pattern count, and uptime. No authentication required. Used for monitoring and load balancer health checks.

#### `POST /v1/feedback`

Accepts false positive and false negative reports. Returns `202 Accepted` immediately.

- **Persistence:** Anonymous feedback metadata is stored in Turso when configured; falls back to stdout logging when Turso is unavailable.
- **`expected_type` field:** For false negatives, users can specify which pattern type they expected (validated against the pattern registry).
- **Anonymous by design:** No API key hash or user identity is stored alongside feedback records. Records contain only: feedback_id, request_id, finding_id, feedback_type, has_comment (boolean), expected_type, and timestamp.
- **Rate limited:** 10 submissions per hour per API key (separate from the global rate limit). Enforced in-memory, never persisted.
- **Security:** Comment text is never stored — only a `has_comment` boolean. No scanned text or secret values are ever persisted.

Aggregate queries are available via `scripts/feedback_report.py` (CLI) to identify false positive hotspots and false negative gaps by pattern type.

### Pydantic Models (`app/models/`)

All request and response bodies are Pydantic v2 models with:
- `Field` descriptions for OpenAPI documentation
- `model_config` with `json_schema_extra` examples (displayed in Swagger UI)
- `model_validator` for enum-like field validation (`redaction_style`, `feedback_type`)

**Request models** (`requests.py`): `ScanRequest`, `RedactRequest`, `FeedbackRequest` (with `expected_type` validated against pattern registry), `KeyCreateRequest`

**Response models** (`responses.py`): `ScanResponse`, `RedactResponse`, `FindingResponse`, `RedactFindingResponse`, `TypeInfo`, `TypesResponse`, `HealthResponse`, `FeedbackResponse`, `KeyCreateResponse`, `ErrorResponse`, `ErrorDetail`, `Span`, `SeveritySummary`

`FindingResponse` has a `from_engine()` classmethod that converts the engine's `Finding` dataclass to the API response model.

### Middleware (`app/middleware/`)

Three middleware layers, executed in order: Auth → Rate Limit → Logging → Route handler.

#### Authentication (`auth.py`)

- Validates `X-API-Key` header on every request except `/v1/health`, `/docs`, and `/v1/openapi.json`
- Checks against a whitelist loaded from the `CLASSIFINDER_API_KEYS` environment variable
- Key format: `ss_live_` prefix (production) or `ss_test_` prefix (sandbox)
- Returns `401` with structured error for missing or invalid keys
- Attaches a SHA-256 hash (first 8 chars) of the key to `request.state` for logging — never the key itself

#### Rate Limiting (`rate_limit.py`)

- In-memory sliding window per API key hash
- Default: 60 requests per minute (configurable via `CLASSIFINDER_RATE_LIMIT_PER_MINUTE`)
- Returns `429 Too Many Requests` with `Retry-After` header when exceeded
- Attaches `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers to every response
- Skips rate limiting on `/v1/health`
- MVP design: single-process only, no Redis

#### Request Logging (`logging.py`)

Emits one structured JSON log line per request to stdout. Logs **only** safe metadata:

```json
{
  "request_id": "req_a1b2c3d4e5f6",
  "api_key_hash": "3f2a91bc",
  "timestamp": "2026-03-22T15:30:00Z",
  "method": "POST",
  "endpoint": "/v1/scan",
  "input_size_bytes": 4096,
  "finding_count": 3,
  "response_time_ms": 7,
  "status_code": 200
}
```

Never logs request bodies, response bodies, or any secret values.

### Application Entry Point (`app/main.py`)

The `create_app()` factory:

1. Creates the FastAPI app with OpenAPI metadata (title, version, description)
2. Adds CORS middleware (allow all origins — agents call from everywhere)
3. Adds custom middleware in reverse order (Starlette inserts at index 0)
4. Injects a `req_`-prefixed UUID on every request via an HTTP middleware
5. Registers exception handlers for validation errors (400), not found (404), internal errors (500), and HTTPExceptions
6. Includes all five routers

All error responses use a consistent envelope: `{"error": {"code": "...", "message": "...", "retry_after": ...}}`

OpenAPI spec is served at `/v1/openapi.json`. Swagger UI is at `/docs`.

### Configuration (`app/config.py`)

All settings come from environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLASSIFINDER_API_KEYS` | `""` | Comma-separated list of valid API keys |
| `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` | `60` | Max requests per key per minute |
| `CLASSIFINDER_MAX_PAYLOAD_BYTES` | `262144` (256 KB) | Max request body size |
| `CLASSIFINDER_VERSION` | `1.0.0` | Version string returned by `/v1/health` |
| `TURSO_DATABASE_URL` | `""` | Turso database URL (optional — enables key provisioning and feedback persistence) |
| `TURSO_AUTH_TOKEN` | `""` | Turso auth token (required if `TURSO_DATABASE_URL` is set) |

Settings are loaded once via `@lru_cache` and accessed through `get_settings()`. Turso is optional — if not configured, key provisioning is disabled and feedback falls back to stdout logging.

---

## Tests

93 tests, all passing. Four test files:

### `tests/test_patterns.py` — 21 tests

Engine-level tests covering:
- True positive detection for each pattern category (AWS keys, Stripe keys, GitHub tokens, etc.)
- True negative verification (clean text produces no findings)
- Test value flagging (known example credentials are marked `is_likely_test_value: true`)
- Redaction output for all three styles
- Multi-secret scanning (multiple secrets in one document)
- Context extraction

### `tests/test_api.py` — 36 tests

Full HTTP integration tests via FastAPI's `TestClient`:

- **Health** (2 tests): no-auth access, auth-accepted-but-optional
- **Types** (4 tests): auth required, returns list, field completeness, severity validation
- **Scan** (12 tests): auth required, invalid key, AWS key detection, clean text, response/finding field completeness, value masking, context inclusion/exclusion, type filtering, confidence filtering, missing fields, rate limit headers
- **Redact** (8 tests): auth required, clean text passthrough, all three redaction styles, invalid style rejection, finding field completeness, no context in redact findings
- **Feedback** (5 tests): auth required, false positive/negative acceptance, invalid type rejection, missing fields
- **Auth** (3 tests): missing header, empty header, error response shape

Tests use a test API key (`ss_test_...`) injected via environment variable before app import, with a high rate limit (1000/min) to avoid interference.

### `tests/test_feedback.py` — 15 tests

Feedback persistence and rate limiting:

- **Store init** (1 test): table creation with local SQLite
- **Insert** (2 tests): row persistence with and without `expected_type`
- **Validation** (4 tests): `expected_type` accepted/rejected against pattern registry, None accepted, JSON schema presence
- **Route persistence** (3 tests): Turso persistence path, stdout fallback, `expected_type` propagation
- **Aggregates** (3 tests): false positive counts by finding_id, false negative gaps by expected_type, volume by day
- **Rate limit** (2 tests): under-limit succeeds, over-limit returns 429

### `tests/test_keys.py` — 12 tests

Key provisioning via Turso:

- **Key creation** (6 tests): success, email normalization, duplicate rejection, invalid email, missing email, no-auth-required
- **Key rotation** (3 tests): rotate success, old key invalidated, auth required
- **Auth integration** (2 tests): Turso-provisioned key works, env var key still works
- **IP rate limit** (1 test): 5 keys per IP per hour

### Running Tests

```bash
python -m pytest tests/ -v          # all tests
python -m pytest tests/test_api.py  # API tests only
python tests/test_patterns.py       # pattern tests standalone
```

---

## Deployment Infrastructure

### Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Environment variables for API keys, rate limits, payload limits, and version are declared with defaults.

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set at least one API key
export CLASSIFINDER_API_KEYS="ss_live_your_key_here_padded_to_48_characters_total"

# Start the dev server
uvicorn app.main:app --reload --port 8000

# Visit Swagger UI
open http://localhost:8000/docs
```

---

## Security Design Decisions

These are deliberate choices, not oversights:

1. **Full secret values are never returned in API responses.** Only masked previews (`AKIA****MPLE`). Competitors like GitGuardian return full values — ClassiFinder intentionally does not.

2. **Request bodies are never logged.** Users are sending secrets by definition. Logging them defeats the product's purpose. Only metadata is logged (request ID, key hash, timestamp, endpoint, payload size, finding count, response time, status code).

3. **API keys are never logged.** Only a SHA-256 hash prefix (first 8 chars) appears in logs.

4. **Feedback is anonymous.** No API key hash or user identity is stored with feedback records. Comment text is never persisted — only a `has_comment` boolean. Abuse prevention uses ephemeral in-memory rate limiting, not stored identity.

5. **The engine is a pure function.** No I/O, no state, no disk writes. Process in memory, return results, discard. This makes the security posture strong — scanned text is never persisted.

---

## What Is Not Built (and Why)

| Feature | Reason |
|---------|--------|
| User accounts | API keys only. No passwords to breach. |
| Dashboard / Web UI | API-only product, built for machines. |
| Redis rate limiting | In-memory is sufficient for MVP. Redis if/when multi-process deployment is needed. |
| Batch endpoint | Post-MVP feature. Single-text scanning covers launch use cases. |
| Framework integrations | LlamaIndex, etc. are post-MVP distribution plays beyond LangChain (which ships with the SDK). |
| Stripe billing | Not needed until paid tiers are active. |

---

## Deployment — Live as of March 23, 2026

### Infrastructure

| Component | Platform | URL |
|-----------|----------|-----|
| Landing page | Cloudflare Pages | https://classifinder.ai |
| API | Fly.io (SJC region) | https://api.classifinder.ai |
| Domain registrar | Hostinger | classifinder.ai |
| DNS | Cloudflare (free tier) | Nameservers: jose.ns.cloudflare.com, pearl.ns.cloudflare.com |
| Form submissions | Formspree (free tier) | Early access request form on landing page |
| TLS certificates | Let's Encrypt (via Fly.io for API, Cloudflare for landing page) | Auto-renewing |

### DNS Records (Cloudflare)

| Type | Name | Content | Proxy Status |
|------|------|---------|-------------|
| A | api | 66.241.125.248 | DNS only |
| AAAA | api | 2a09:8280:1::e7:9e62:0 | DNS only |
| Worker | classifinder.ai | classifinder-site | Proxied |
| Worker | www.classifinder.ai | classifinder-site | Proxied |

### Fly.io Configuration

- App name: `classifinder`
- Region: `sjc` (San Jose)
- VM: `shared-cpu-1x`, 256MB RAM
- Scale-to-zero enabled (`auto_stop_machines = 'stop'`, `min_machines_running = 0`)
- Health check: `GET /v1/health` every 30s
- Secrets managed via `fly secrets set` (never in fly.toml or committed files)

### Environment Variables (Production)

| Variable | Where Set |
|----------|-----------|
| `CLASSIFINDER_API_KEYS` | `fly secrets` (encrypted) |
| `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` | `fly secrets` |
| `CLASSIFINDER_MAX_PAYLOAD_BYTES` | `fly secrets` |
| `CLASSIFINDER_VERSION` | `fly secrets` |

### Landing Page (`classifinder-site/`)

Astro-based static site deployed via GitHub Actions to Cloudflare Workers. Noir/pulp fiction visual identity with Playfair Display, Source Serif 4, and DM Mono fonts. Dark mode default with a "Light?" toggle that reveals hidden secrets as background watermarks.

Sections: hero with stats (71 types, <5ms, 0 bytes of your text stored, open source engine), interactive demo calling `/v1/demodemo`, "How It Works" (install/scan/ship + LangChain + MCP examples), competitive comparison table, trust section (open source engine, honest limitations, compliance), pricing tiers (Free + Coming Soon), self-serve key provisioning form, and footer.

Key provisioning form calls `POST /v1/keys/create` directly, with Formspree as a fallback.

### CI/CD Pipeline

Push to `main` triggers GitHub Actions (`.github/workflows/deploy.yml`):

1. **Test** — Installs dependencies, runs full pytest suite (93 tests)
2. **Deploy** — If tests pass, deploys to Fly.io via `flyctl deploy --remote-only`

Uses `FLY_API_TOKEN` secret for Fly.io authentication. No manual deploys needed.

### Deployment Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Standard deployment (Fly.io, Railway, etc.) |
| `Dockerfile.lambda` | AWS Lambda deployment with Lambda Web Adapter |
| `fly.toml` | Fly.io configuration |
| `.github/workflows/deploy.yml` | CI/CD: test → deploy to Fly.io |
| `.dockerignore` | Excludes tests, docs, .git from Docker builds |

---

## MCP Server (`classifinder-mcp/`) — Built March 25, 2026

An MCP (Model Context Protocol) server that exposes ClassiFinder's scan and redact capabilities as tools for AI agents. Published as `classifinder-mcp` on PyPI.

### What It Does

Gives any MCP-compatible agent (Claude Code, Cursor, etc.) two tools:

- **`classifinder_scan`** — Scan text for leaked secrets. Returns findings with type, severity, confidence, and remediation guidance.
- **`classifinder_redact`** — Replace detected secrets with safe placeholders. Returns clean text safe to forward to any LLM.

### Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | FastMCP (`mcp>=1.0.0`) |
| Transport | stdio |
| HTTP client | ClassiFinder Python SDK (`classifinder>=0.1.3`) |
| Package manager | Hatch |
| Python | 3.10+ |

### How It Works

The server is a thin wrapper around the ClassiFinder Python SDK. It lazy-initializes a `ClassiFinder` client using the `CLASSIFINDER_API_KEY` environment variable, then exposes two `@mcp.tool()` functions that call `client.scan()` and `client.redact()` respectively. Responses are serialized to JSON strings for the agent to consume.

### Project Structure

```
classifinder-mcp/
├── src/classifinder_mcp/
│   ├── __init__.py
│   └── server.py          # FastMCP server with scan + redact tools
├── pyproject.toml          # Hatch build, classifinder-mcp entry point
├── README.md
├── LICENSE                 # MIT
└── dist/                   # Built wheel + sdist
```

### Installation & Configuration

```bash
pip install classifinder-mcp
```

Agent config (Claude Code / Cursor):

```json
{
  "mcpServers": {
    "classifinder": {
      "command": "classifinder-mcp",
      "env": {
        "CLASSIFINDER_API_KEY": "ss_live_your_key_here"
      }
    }
  }
}
```

### Design Decisions

- **Depends on the SDK, not the API directly.** Reuses the SDK's retry logic, error handling, and Pydantic models rather than duplicating HTTP calls.
- **Lazy client initialization.** The `ClassiFinder` client is created on first tool call, not at import time. This keeps startup fast and defers the API key check until actually needed.
- **Returns structured JSON strings.** Tool outputs are JSON so agents can parse findings programmatically, but with `indent=2` for human readability in logs.
- **MIT licensed.** Same as the SDK and engine — the open-source parts of the stack.

---

## Pattern Quality Testing Framework (`classifinder-tests/`) — Built March 28–29, 2026

A dedicated testing and analysis framework for measuring detection quality across both engines (API server and standalone open-source). Separate from the API server's unit/integration tests — this framework validates pattern accuracy, confidence calibration, false positive rates, and cross-engine parity.

### What It Does

- **Corpus-based testing** — Organized test data (known secrets, benign text, adversarial edge cases) with self-documenting `# expect:` headers in each file
- **Cross-engine parity** — Verifies the API engine and standalone `classifinder-engine` produce identical results
- **Baseline regression detection** — Tracks false positive counts and true positive confidence scores against committed baselines; flags regressions
- **Report generation** — Produces JSON reports for corpus stats, confidence distributions, parity divergences, FP analysis, and TP tracking

### Project Structure

```
classifinder-tests/
├── lib/                        # Shared utilities
│   ├── engine_wrapper.py       # Unified interface to both scanner engines
│   ├── schema.py               # Pydantic models for JSON report output
│   ├── corpus_parser.py        # Parse "# expect:" headers from test files
│   ├── pattern_library_parser.py # Parse pattern-library.md into structured data
│   ├── comparator.py           # Cross-engine parity comparison
│   └── parity_allowlist.py     # Known intentional divergences (empty by default)
├── corpus/                     # Test data (71 patterns × 4 corpus types)
│   ├── known-secrets/          # Text that SHOULD trigger findings (by category)
│   ├── benign/                 # Text that should NOT trigger findings
│   │   ├── prose/              # Real documentation and blog content
│   │   ├── code/               # Source code without secrets
│   │   ├── config-templates/   # .env.example, docker-compose templates
│   │   └── encoded/            # Base64, UUIDs, hashes
│   └── adversarial/            # Edge cases: truncated keys, near-misses, wrong prefixes
├── tests/                      # pytest CI gates (11 test files)
│   ├── test_pattern_library.py # Validates all 71 pattern examples from docs
│   ├── test_known_secrets.py   # All known-secrets corpus files detected correctly
│   ├── test_benign.py          # Benign corpus produces zero findings
│   ├── test_adversarial.py     # Edge cases behave correctly
│   ├── test_parity.py          # Both engines produce identical results
│   ├── test_engine_wrapper.py  # Engine abstraction tests
│   ├── test_corpus_parser.py   # Header parsing tests
│   ├── test_pattern_library_parser.py
│   ├── test_comparator.py      # Parity logic tests
│   └── test_schema.py          # Pydantic model tests
├── reports/                    # Analysis scripts → JSON output
│   ├── corpus_report.py        # Per-pattern precision, recall, confidence
│   ├── confidence_analysis.py  # Confidence distributions, flags weak patterns
│   ├── parity_report.py        # Detailed cross-engine divergence report
│   ├── fp_report.py            # False positives + baseline regression detection
│   ├── tp_report.py            # True positive confidence + baseline regression
│   └── format_text.py          # Pretty-print any report JSON as table
├── baselines/                  # Committed regression baselines
│   ├── fp_baseline.json        # False positive counts per pattern
│   └── tp_baseline.json        # True positive confidence per pattern
├── scripts/
│   └── check_engine_sync.sh    # Verify both engines have identical code
└── output/                     # Generated JSON reports (gitignored)
```

### Corpus File Convention

Every test file is self-documenting with headers:

```
# expect: aws_access_key
# expect: aws_secret_key >= 0.8
# description: AWS credentials in a shell script
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=aB3dE6gH9jK2mN5pQ8sT...
```

No external manifest needed. The parser extracts expected types, optional confidence floors, and description from headers, then passes the body text to the scanner.

### Engine Wrapper

All tests and reports use `EngineWrapper("api")` or `EngineWrapper("standalone")` — never import scanner engines directly. This normalizes the two different engine interfaces into a consistent `EngineResult` dataclass and handles monorepo path resolution.

### Running

```bash
cd classifinder-tests

# Run all tests
PYTHONPATH=. python -m pytest tests/ -v

# Skip slow corpus scans
PYTHONPATH=. python -m pytest -m "not slow" -v

# Generate reports
PYTHONPATH=. python reports/corpus_report.py        # precision, recall, confidence
PYTHONPATH=. python reports/confidence_analysis.py  # distribution + weak pattern flags
PYTHONPATH=. python reports/parity_report.py        # cross-engine divergences
PYTHONPATH=. python reports/fp_report.py            # false positive baseline regression
PYTHONPATH=. python reports/tp_report.py            # true positive confidence regression

# Pretty-print any report
PYTHONPATH=. python reports/format_text.py output/*.json
```

---

## Documentation Files

All project documentation lives in the project root:

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Project overview and rules for Claude Code |
| `what-was-built.md` | This document — complete technical state |
| `classifinder-architecture.md` | System design, security rules, confidence scoring, pattern library structure |
| `classifinder-api-spec.md` | Complete API specification with request/response schemas and examples |
| `classifinder-marketing-strategy.md` | Competitive positioning, gaps we fill, compliance messaging, launch channels |
| `FASTAPI-IMPLEMENTATION-PLAN.md` | Plan used to build the FastAPI wrapper (historical, task complete) |
| `DEPLOYMENT-PLAN.md` | Plan used to deploy to Fly.io and Lambda (historical, task complete) |

### Research Files (in project knowledge)

| File | Contents |
|------|----------|
| `Regex-based_parsing_API_for_agents.md` | Original Grok conversation about API ideas |
| `secret-scanner-research-prompts.md` | Prompts sent to Grok/Gemini for competitive research |
| `Responses_from_Grok_and_Gemini.md` | Round 1: Competitive landscape and market sizing |
| `Responses_from_Grok_and_Gemini_2.md` | Round 2: GitGuardian/Nightfall API details, Betterleaks, framework gaps, self-host risk |
| `Responses_from_Grok_and_Gemini_3.md` | Round 3: BPE tokenization, GitGuardian MCP, OWASP language, compliance control IDs |
| `deployment-research-prompt.md` | Prompt sent for deployment platform research |
| `Grok_and_Gemini_deployment-research-prompt_answers.md` | Deployment platform comparison (Railway, Fly.io, Render, Lambda, Cloudflare Workers) |

---

## What's Been Completed Since Launch

| Milestone | Date | Details |
|-----------|------|---------|
| Python SDK + LangChain integration | March 2026 | `pip install classifinder` — thin httpx client with sync/async, built-in retries, LangChain `ClassiFinderGuard` Runnable. Published to PyPI. |
| MCP Server | March 25, 2026 | `pip install classifinder-mcp` — FastMCP server exposing `classifinder_scan` and `classifinder_redact` tools for Claude Code, Cursor, and any MCP-compatible agent. Published to PyPI. |
| Open-source engine | March 2026 | `classifinder-engine/` — standalone MIT-licensed scanner so users can audit the code that touches their data. |
| AI provider patterns | March 2026 | Added OpenAI, Anthropic, and Cohere API key detection patterns (4 patterns in `patterns/ai.py`). Total pattern count: 71. |
| Key provisioning | March 2026 | Self-serve API key generation via `POST /v1/keys/create` and rotation via `POST /v1/keys/rotate`. Turso-backed with in-memory LRU cache, IP rate limiting (5 keys/IP/hour), email uniqueness. |
| Feedback persistence | March 26, 2026 | `POST /v1/feedback` now persists anonymous metadata to Turso. Added `expected_type` field for false negatives (validated against pattern registry). Feedback-specific rate limit (10/hour/key). CLI report script for aggregate queries. 93 total tests. |
| CI/CD pipeline | March 27, 2026 | GitHub Actions: push to main → run 93 tests → deploy to Fly.io. No manual deploys needed. |
| Domain migration | March 27, 2026 | Migrated from `classifinder.tech` to `classifinder.ai` across all 6 repos. Updated DNS, Fly.io cert, Cloudflare Workers route, SDK 0.1.3 + MCP 0.1.1 published to PyPI with new default URL. `.tech` 301-redirects to `.ai`. |
| Pattern quality framework | March 28–29, 2026 | `classifinder-tests/` — dedicated testing framework with corpus-based testing, cross-engine parity validation, confidence analysis, false positive/true positive baseline regression detection, and 5 report generators. |

## What's Next

Priority order for the next phase:

1. **Launch** — Show HN, Product Hunt, r/LocalLLaMA, r/devops, X/Twitter. Narrative: "Every secret scanner was built for Git. This one's built for AI."
2. **Expand pattern coverage** — More provider-specific keys, improved Luhn validation for credit cards.
3. **Content marketing** — Blog posts from the marketing strategy doc. "The $82,000 API Key" is the strongest story.
4. **Cursor Directory submission** — Submit `classifinder-mcp` as a plugin to cursor.directory.
