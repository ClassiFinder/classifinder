# ClassiFinder

Lightweight, stateless API that scans text for leaked secrets and credentials. Returns structured JSON with type, confidence, severity, span locations, and optionally redacted text. Built for AI agents, LLM pipelines, and CI/CD.

## Tech Stack

- Python 3.12+
- FastAPI + Uvicorn
- Pydantic v2
- Turso (hosted SQLite) — optional, for key provisioning and anonymous feedback persistence
- libsql-experimental for Turso connectivity

## Commands

```bash
python -m pytest tests/ -v                    # run all tests (93 tests)
python tests/test_patterns.py                 # run pattern tests standalone
uvicorn app.main:app --reload --port 8000     # dev server
docker build -t classifinder .                # build Docker image
docker build -f Dockerfile.lambda -t classifinder-lambda .  # build Lambda image
```

## Architecture

- `app/engine/` — Core scanner engine. **Do not modify.** Tested and working.
  - `scanner.py` — `scan(text, types?, min_confidence?, include_context?) -> List[Finding]`
  - `redactor.py` — `redact(text, findings, style) -> (redacted_text, redaction_map)`
  - `entropy.py` — Shannon entropy calculator
  - `patterns/registry.py` — `PATTERN_REGISTRY` list and `SecretPattern` dataclass
  - `patterns/{cloud,payment,vcs,comms,database,generic,ai}.py` — 82 detection patterns
- `app/key_store.py` — Turso-backed API key lifecycle (generate, lookup, rotate)
- `app/feedback_store.py` — Anonymous feedback persistence + aggregate queries
- `app/routes/` — FastAPI route handlers
  - `scan.py` — `POST /v1/scan`
  - `redact.py` — `POST /v1/redact`
  - `types.py` — `GET /v1/types`
  - `health.py` — `GET /v1/health` (no auth required)
  - `feedback.py` — `POST /v1/feedback` (Turso persistence + stdout fallback, feedback-specific rate limit)
  - `keys.py` — `POST /v1/keys/create`, `POST /v1/keys/rotate`
  - `demo.py` — `POST /v1/demodemo` (no auth, for landing page demo)
- `app/models/` — Pydantic v2 request/response models
  - `requests.py` — `ScanRequest`, `RedactRequest`, `FeedbackRequest` (with `expected_type`), `KeyCreateRequest`
  - `responses.py` — `ScanResponse`, `RedactResponse`, `FindingResponse`, `TypesResponse`, `HealthResponse`, `KeyCreateResponse`, etc.
- `app/middleware/` — Auth, rate limiting, logging
  - `auth.py` — API key validation via `X-API-Key` header (env vars + Turso lookup)
  - `rate_limit.py` — In-memory sliding window per key hash
  - `logging.py` — Metadata-only JSON log lines to stdout
- `app/config.py` — Settings from env vars (`CLASSIFINDER_API_KEYS`, `CLASSIFINDER_RATE_LIMIT_PER_MINUTE`, `CLASSIFINDER_MAX_PAYLOAD_BYTES`, `CLASSIFINDER_VERSION`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`)
- `app/main.py` — App factory, CORS, middleware wiring, exception handlers
- `scripts/feedback_report.py` — CLI tool for querying feedback trends
- `tests/test_patterns.py` — 21 engine/pattern tests
- `tests/test_api.py` — 36 API integration tests
- `tests/test_feedback.py` — 15 feedback persistence + rate limit tests
- `tests/test_keys.py` — 12 key provisioning tests

## Key Design Rules

- **Never log request bodies.** Users send us their secrets. Log only metadata: request_id, api_key_hash, timestamp, endpoint, input_size_bytes, finding_count, response_time_ms, status_code.
- **Never return full secret values.** Use `value_preview` (masked with first 4 + last 4 chars).
- **All responses are JSON.** Errors use `{"error": {"code": "...", "message": "..."}}`.
- **API key auth** via `X-API-Key` header. Key prefix: `ss_live_` (prod) or `ss_test_` (sandbox). Skip auth on `/v1/health` only.
- **Rate limiting** is in-memory for MVP. No Redis.

## Deployment — Live

| Component | Platform | URL |
|-----------|----------|-----|
| Landing page | Cloudflare Pages | https://classifinder.ai |
| API | Fly.io (SJC region) | https://api.classifinder.ai |
| Domain registrar | Hostinger | classifinder.ai |
| DNS | Cloudflare (free tier) | jose.ns.cloudflare.com, pearl.ns.cloudflare.com |
| Form submissions | Formspree (free tier) | Early access form on landing page |

Fly.io config: `shared-cpu-1x`, 256MB RAM, scale-to-zero enabled. Secrets managed via `fly secrets set` — never in committed files.

### Deployment Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Standard deployment (Fly.io) |
| `Dockerfile.lambda` | AWS Lambda with Lambda Web Adapter |
| `fly.toml` | Fly.io configuration |
| `.github/workflows/deploy.yml` | CI/CD: push to main → test (93 tests) → deploy to Fly.io |
| `.dockerignore` | Excludes tests, docs, .git from Docker builds |

## Reference Docs (in `docs/`)

- `what-was-built.md` — Complete technical description of everything implemented
- `technical-description.md` — Detailed architecture and implementation reference
- `layman-description.md` — Non-technical explanation of the product
- `a-note-on-honesty.md` — Trust/verifiability analysis for the no-storage claim
- `classifinder-api-spec.md` — Complete API specification with request/response schemas. **Source of truth for endpoint contracts.**
- `classifinder-architecture.md` — System design, security rules, confidence scoring algorithm, pattern library structure
- `classifinder-marketing-strategy.md` — Competitive positioning, compliance messaging, launch channels
- `FASTAPI-IMPLEMENTATION-PLAN.md` — Plan used to build the FastAPI wrapper (historical, complete)
- `files/DEPLOYMENT-PLAN.md` — Plan used to deploy to Fly.io and Lambda (historical, complete)

## Code Style

- Type hints on all functions
- Docstrings on modules and public functions
- Pydantic v2 models with `model_config` and `Field` descriptions
- Include realistic `json_schema_extra` examples in Pydantic models (FastAPI uses these for Swagger UI)
- PEP 8, 100 char lines

## Important Notes

- The engine is a pure function: text in, findings out. No I/O, no state.
- The `/v1/redact` endpoint is our strongest differentiator. Its `redacted_text` output is what agents use as LLM preprocessing middleware.
- Competitor GitGuardian returns full secret values in their API. We intentionally do not — this is a security feature, not a limitation.
- Feedback is anonymous by design — no API key hash stored with feedback records.
- Engine code in `app/engine/` must stay in sync with `classifinder-engine/`. A pre-commit hook enforces this, but **hooks don't transfer on clone**. After cloning, run:
  ```bash
  cp scripts/check_engine_sync.sh .git/hooks/pre-commit-sync
  cat > .git/hooks/pre-commit << 'HOOK'
  #!/usr/bin/env bash
  STAGED=$(git diff --cached --name-only)
  if echo "$STAGED" | grep -q "^app/engine/"; then
      echo "Engine files staged — checking sync with classifinder-engine/..."
      bash "$(git rev-parse --show-toplevel)/scripts/check_engine_sync.sh"
  fi
  HOOK
  chmod +x .git/hooks/pre-commit
  ```
