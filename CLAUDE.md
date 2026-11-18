# ClassiFinder API — notes for AI coding agents

Stateless API that scans text for leaked secrets and prompt-injection markers. Returns structured JSON with type, confidence, severity, span locations, and optionally redacted text. Built for AI agents, LLM pipelines, and CI/CD.

For what the API does and how to call or self-host it, read [README.md](./README.md). This file covers what you need to know before changing the code.

## Tech Stack

- Python 3.12+, FastAPI + Uvicorn, Pydantic v2
- Turso (hosted SQLite, via `libsql-experimental`) — optional, only for the hosted service's key provisioning and feedback storage. Without it, auth uses `CLASSIFINDER_API_KEYS` and feedback goes to stdout.

## Commands

```bash
pip install -r requirements.lock
CLASSIFINDER_API_KEYS=dev-key uvicorn app.main:app --reload --port 8000   # dev server
python -m pytest tests/ -q                     # full suite (several thousand tests, under 10s)
ruff check .                                   # lint
mypy app/                                      # type check
shellcheck scripts/check_engine_sync.sh
python scripts/redos_audit.py                  # ReDoS audit of the pattern regexes
docker build -f Dockerfile.selfhost -t classifinder-selfhost .
```

Live pattern count: `curl -s localhost:8000/v1/health` (`patterns_loaded`), or `len(PATTERN_REGISTRY)`. Don't hard-code counts in docs you don't have to — they go stale with every pattern merge, and `classifinder-tests` has a lint that fails on mismatched counts.

## Setup after cloning — install the pre-commit hook

Git hooks don't transfer on clone. Install the one this repo depends on:

```bash
cp scripts/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

It runs two checks when relevant files are staged:

- **Engine sync** (`scripts/check_engine_sync.sh`) — `app/engine/` must be identical to the sibling `../classifinder-engine/` checkout. Clone both into the same parent folder.
- **Pattern provenance** (`scripts/check_pattern_provenance.py`) — see below.

CI (`.github/workflows/deploy.yml`) runs the test suite only. It does **not** run either check, so the hook is the only gate.

## Architecture

- `app/engine/` — Core scanner. A pure function: text in, findings out, no I/O, no state. Change it only with the full test suite green and the same change made in `classifinder-engine`.
  - `scanner.py` — `scan(text, types?, min_confidence?, include_context?) -> List[Finding]`: matching, confidence scoring, dedup, context snippets (every secret in a snippet is masked, not just the reported one)
  - `redactor.py` — `redact(text, findings, style) -> (redacted_text, redaction_map)`; styles `label`, `mask`, `hash`
  - `entropy.py` — Shannon entropy
  - `decoders.py` — base64 pre-scan decoding
  - `false_positives.py` + `data/fp_wordlist.txt` — known-junk filter (skipped for prompt-injection patterns)
  - `patterns/registry.py` — `PATTERN_REGISTRY` and the `SecretPattern` dataclass
  - `patterns/{ai,cloud,comms,data,database,devops,generic,identity,payment,vcs}.py` — secret patterns, one module per category
  - `patterns/prompt_injection.py` — prompt-injection markers (`provider="prompt_injection"`, severity capped at `high`). Each carries `safe_mcp_ids` cross-referencing the SAFE-MCP technique catalog (CC-BY-4.0); the field surfaces on every `Finding`.
- `app/routes/` — FastAPI handlers
  - `scan.py` — `POST /v1/scan`
  - `redact.py` — `POST /v1/redact`
  - `types.py` — `GET /v1/types`
  - `health.py` — `GET /v1/health`
  - `feedback.py` — `POST /v1/feedback` (Turso persistence with stdout fallback; its own rate limit)
  - `keys.py` — `POST /v1/keys/create`, `POST /v1/keys/rotate` (hosted service only; needs Turso)
  - `demo.py` — `POST /v1/demodemo` (for the landing-page demo)
- `app/models/` — Pydantic v2 models: `requests.py` (`ScanRequest`, `RedactRequest`, `FeedbackRequest`, `KeyCreateRequest`), `responses.py`
- `app/middleware/` — wired so requests pass Auth → Rate limit → Logging
  - `auth.py` — `X-API-Key` validation (env keys, then Turso). Exempt: `/v1/health`, `/docs`, the OpenAPI JSON, `/v1/keys/create`, `/v1/demodemo`, and `OPTIONS`.
  - `rate_limit.py` — in-memory sliding window per key hash, per worker. No Redis.
  - `logging.py` — one metadata-only JSON line per request to stdout
- `app/key_store.py` — Turso-backed key lifecycle. Generated keys are `ss_live_` + 40 hex; keys starting `ss_test_` are treated as test keys.
- `app/feedback_store.py` — anonymous feedback persistence + aggregate queries
- `app/config.py` — the only place that reads environment variables: `CLASSIFINDER_API_KEYS`, `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` (60), `CLASSIFINDER_MAX_PAYLOAD_BYTES` (262144), `CLASSIFINDER_VERSION`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`
- `app/main.py` — app factory, CORS, middleware wiring, JSON exception handlers
- `scripts/` — `pre-commit` (the hook above), `check_engine_sync.sh`, `check_pattern_provenance.py`, `add_source_comments.py`, `redos_audit.py`, `feedback_report.py` (feedback trends CLI)
- `tests/` — pytest + FastAPI TestClient. `pattern_test_cases.py` holds per-pattern positives/negatives that `test_pattern_harness.py` expands into tests; `test_patterns.py` holds hand-written engine tests; `test_redos.py` and `test_context_masking.py` guard the two most recent engine fixes.

## Rules — do not break these

Users send us their secrets.

- **Never log request bodies.** Log only metadata: request_id, api_key_hash, timestamp, endpoint, input_size_bytes, finding_count, response_time_ms, status_code.
- **Never return full secret values.** Use `value_preview` (first 4 + last 4 chars), and keep context snippets masked.
- **Never store scanned text.** Process in memory, return, discard.
- **API keys never in logs or request state** — only the first 8 hex chars of their SHA-256.
- **All responses are JSON.** Errors use `{"error": {"code": "...", "message": "...", "retry_after": ...}}`.
- **Feedback is anonymous** — no API key hash is stored with feedback records.

## Adding or changing patterns

- **Provenance is mandatory.** Every `re.compile()` in `app/engine/patterns/*.py` needs a source comment within 5 lines above it. Accepted forms: `# Source: <URL>`, `# Format per <URL>`, `# Pattern attribution: Betterleaks MIT` / `SPDB CC-BY-4.0`, `# Independently authored — <rationale>`, `# Vendor-published format`. Never use TruffleHog (AGPL-3.0) as a source. Record the source in `ATTRIBUTION.md`.
- **Fixtures are synthetic.** Never commit a real credential, even a revoked one. Build test values from fragments (`"sk" + "_live_" + …`) so no complete key literal sits in the source — this also keeps GitHub push protection from blocking the public `classifinder-engine` push.
- **Add cases** to `tests/pattern_test_cases.py` and engine tests to `tests/test_patterns.py`, then run the full suite.
- **Mirror the change** into `classifinder-engine` (same files under `classifinder_engine/`) and merge the two PRs as a pair: API repo first, engine second.
- **Run `scripts/redos_audit.py`** on new regexes; the scanner runs every pattern on every request.

## Deployment

- **Hosted API** — Fly.io (`fly.toml`: SJC, `shared-cpu-1x`, 256 MB, scale-to-zero) at https://api.classifinder.ai. A push to `main` runs `test`, then `deploy` (Fly) and `publish-image` in `.github/workflows/deploy.yml`. Secrets live in `fly secrets`, never in committed files.
- **Self-host image** — `publish-image` builds `Dockerfile.selfhost` (no Turso driver, `linux/amd64` + `linux/arm64`) and pushes it to `ghcr.io/classifinder/classifinder` with SBOM and SLSA provenance.

| File | Purpose |
|------|---------|
| `Dockerfile` | Hosted deployment (Fly.io) |
| `Dockerfile.selfhost` | Public self-host image |
| `Dockerfile.lambda` | AWS Lambda via Lambda Web Adapter (not used by CI) |
| `fly.toml` | Fly.io configuration |
| `.dockerignore` | Keeps tests, docs and `.git` out of images |

## Code Style

- Type hints on all functions; docstrings on modules and public functions
- Pydantic v2 models with `model_config` and `Field` descriptions, plus realistic `json_schema_extra` examples (they appear in Swagger UI at `/docs`)
- PEP 8, 100-char lines

## Context

- `/v1/redact` is the core use case: its `redacted_text` is what agents put in front of an LLM as preprocessing.
- Not returning full secret values is a deliberate security property, not a limitation.
- Endpoint contracts, architecture notes and the pattern-tuning guide live in the maintainers' private docs vault (`classifinder-knowledge`); this repo's `classifinder-api-spec.md` and `classifinder-architecture.md` are older copies.
