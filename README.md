# ClassiFinder

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE) [![Test & Deploy](https://github.com/ClassiFinder/classifinder/actions/workflows/deploy.yml/badge.svg)](https://github.com/ClassiFinder/classifinder/actions/workflows/deploy.yml) [![Image: GHCR](https://img.shields.io/badge/image-ghcr.io%2Fclassifinder%2Fclassifinder-2496ED?logo=docker&logoColor=white)](https://github.com/ClassiFinder/classifinder/pkgs/container/classifinder)

**A stateless API that finds leaked secrets and prompt-injection markers in text — built for AI agents, LLM pipelines, and CI/CD.**

Every secret scanner was built for Git. ClassiFinder is built for the text that never reaches a repo: prompts, model outputs, tool-call arguments, logs, tickets, and chat transcripts. Send it a string; get back structured JSON with each finding's type, severity, confidence, exact span, and a masked preview — or the same text with the secrets redacted.

This repository is the server behind [api.classifinder.ai](https://api.classifinder.ai). It's MIT-licensed, and the same code ships as a self-host Docker image.

- **469 detection patterns** — cloud, AI/LLM providers, payments, VCS and package registries, databases, comms and observability tools, identity, generic high-entropy credentials, plus prompt-injection markers mapped to the [SAFE-MCP](https://github.com/safe-mcp/safe-mcp) technique catalog.
- **Stateless by design** — no database of scanned text, no request-body logging, and full secret values never leave the server.
- **Runs anywhere** — hosted API, one `docker run`, or from source.

## Contents

- [Quick start](#quick-start)
- [API](#api)
- [Self-host with Docker](#self-host-with-docker)
- [Privacy guarantees](#privacy-guarantees)
- [How scoring works](#how-scoring-works)
- [Run from source](#run-from-source)
- [Repository layout](#repository-layout)
- [Ecosystem](#ecosystem)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Quick start

**Hosted** — get a free key at [classifinder.ai](https://classifinder.ai), then:

```bash
curl -s -X POST https://api.classifinder.ai/v1/scan \
  -H "X-API-Key: $CLASSIFINDER_API_KEY" -H 'Content-Type: application/json' \
  -d '{"text":"Deploy with AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH"}'
```

**Self-hosted** — one container, no database, no outbound calls:

```bash
docker run -d --name classifinder -p 8000:8000 \
  -e CLASSIFINDER_API_KEYS=change-me \
  ghcr.io/classifinder/classifinder:latest
```

**Python** — the [SDK](https://pypi.org/project/classifinder/) works with either:

```python
from classifinder import ClassiFinder

client = ClassiFinder(api_key="change-me", base_url="http://localhost:8000")  # omit base_url for the hosted API
result = client.redact("my key is AKIAQWERTYUIOPASDFGH")
print(result.redacted_text)  # my key is [AWS_ACCESS_KEY_REDACTED]
```

## API

All endpoints except `/v1/health` require an `X-API-Key` header. Interactive docs (Swagger UI) are served at `/docs`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/scan` | Detect secrets and prompt-injection markers |
| `POST` | `/v1/redact` | Detect, then return the text with findings replaced |
| `GET` | `/v1/types` | List every detection pattern with its provider, severity, and description |
| `GET` | `/v1/health` | Status, version, and number of patterns loaded (no auth) |
| `POST` | `/v1/feedback` | Report a false positive or false negative (anonymous) |

`/v1/keys/*` exists for key provisioning on the hosted service. A self-hosted instance authenticates with `CLASSIFINDER_API_KEYS` and doesn't need it.

### `POST /v1/scan`

| Field | Type | Default | Description |
|---|---|---|---|
| `text` | string | — | The text to scan (max 256 KB by default). |
| `types` | string[] | `["all"]` | Restrict to specific pattern IDs from `/v1/types`. |
| `min_confidence` | float | `0.5` | Drop findings below this confidence (0.0–1.0). |
| `include_context` | bool | `true` | Include a short snippet around each finding, with secrets masked. |

```json
{
  "request_id": "req_4072110c3fa2",
  "scan_time_ms": 0,
  "findings_count": 1,
  "findings": [
    {
      "id": "f_001",
      "type": "aws_access_key",
      "type_name": "AWS Access Key ID",
      "provider": "aws",
      "severity": "critical",
      "confidence": 0.99,
      "value_preview": "AKIA****DFGH",
      "span": { "start": 30, "end": 50 },
      "context": "Deploy with AWS_ACCESS_KEY_ID=AKIA****DFGH",
      "is_likely_test_value": false,
      "recommendation": "Rotate this key immediately in the AWS IAM console. Audit its usage via CloudTrail. If paired with a secret key, rotate both.",
      "matched_pattern": "aws_access_key_v1",
      "safe_mcp_ids": []
    }
  ],
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 }
}
```

`span` is a character offset into your input, so you can highlight or slice the original text yourself. Prompt-injection findings carry `safe_mcp_ids` (for example, `"Ignore all previous instructions…"` returns `pi_instruction_override` tagged `SAFE-T1102`).

### `POST /v1/redact`

Takes the same `text`, `types`, and `min_confidence` fields, plus `redaction_style`:

| Style | Output |
|---|---|
| `label` (default) | `[AWS_ACCESS_KEY_REDACTED]` |
| `mask` | `AKIA****************` (first four characters kept) |
| `hash` | `[REDACTED:sha256:a93e68f8]` — stable per value, useful for deduplication |

```json
{
  "request_id": "req_2b2d494fe55e",
  "scan_time_ms": 0,
  "findings_count": 1,
  "redacted_text": "Deploy with AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]",
  "findings": [
    {
      "id": "f_001",
      "type": "aws_access_key",
      "severity": "critical",
      "confidence": 0.99,
      "span": { "start": 30, "end": 50 },
      "redacted_as": "[AWS_ACCESS_KEY_REDACTED]"
    }
  ],
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 }
}
```

### Errors

Every error is JSON with the same envelope:

```json
{"error": {"code": "invalid_api_key", "message": "Missing, malformed, or revoked API key. Pass your key in the X-API-Key header.", "retry_after": null}}
```

`retry_after` is set (in seconds) on `429` rate-limit responses.

## Self-host with Docker

The image at `ghcr.io/classifinder/classifinder` is built from [`Dockerfile.selfhost`](./Dockerfile.selfhost) in this repo on every merge to `main`, from the same commit that deploys production — so a self-hosted instance has the same pattern set as the hosted API.

- `linux/amd64` and `linux/arm64`, `python:3.12-slim` base, runs as a non-root user.
- No database, no volume, no outbound calls. Your text never leaves your network.
- Ships with an SBOM and SLSA build provenance.

```yaml
# docker-compose.yml
services:
  classifinder:
    image: ghcr.io/classifinder/classifinder:latest
    ports: ["127.0.0.1:8000:8000"]
    environment:
      CLASSIFINDER_API_KEYS: ${CLASSIFINDER_API_KEYS:?set a key}
      CLASSIFINDER_RATE_LIMIT_PER_MINUTE: "600"
    read_only: true
    tmpfs: [/tmp]
    restart: unless-stopped
```

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CLASSIFINDER_API_KEYS` | *(empty)* | **Required.** Comma-separated keys accepted in `X-API-Key`. With none set, every request returns `401`. Use something long and random. |
| `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` | `60` | Requests per minute per key. |
| `CLASSIFINDER_MAX_PAYLOAD_BYTES` | `262144` | Max request body (256 KB). |
| `WEB_CONCURRENCY` | `2` | Uvicorn workers. The rate limiter is in-memory and per worker, so the effective limit is workers × the per-minute value. |

### Tags

| Tag | Meaning |
|---|---|
| `latest` | Current `main`, same build as production |
| `YYYY.MM.DD-<sha7>` | Immutable build from a given day and commit — pin this in production |
| `sha-<full sha>` | Immutable, by commit |

### Verifying the image

```bash
docker buildx imagetools inspect ghcr.io/classifinder/classifinder:latest --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/classifinder/classifinder:latest --format '{{ json .SBOM }}'
```

The server is plain Python under `/app` in the image, so you can read exactly what runs. Full guide: [classifinder.ai/self-host](https://classifinder.ai/self-host).

## Privacy guarantees

ClassiFinder's whole job is to receive secrets, so these rules are enforced in code, not policy:

1. **Request bodies are never logged.** [`app/middleware/logging.py`](./app/middleware/logging.py) writes one metadata-only JSON line per request: request id, API-key hash prefix, endpoint, input size, finding count, latency, and status code.
2. **Full secret values are never returned.** Findings carry `value_preview` (first 4 + last 4 characters), and `context` snippets mask every secret in them — not just the one being reported.
3. **Scanned text is never stored.** The scanner is a pure function with no I/O; the API holds nothing between requests.
4. **API keys never appear in logs or request state** — only the first 8 characters of their SHA-256 hash.
5. **Feedback is anonymous.** `/v1/feedback` stores the report, not who sent it.

The scanning engine is also published on its own as [`classifinder-engine`](https://github.com/ClassiFinder/classifinder-engine) (zero dependencies, `pip install classifinder-engine`), so you can audit or embed the exact code that touches your data. The two copies are kept byte-identical (see [Contributing](#contributing)).

## How scoring works

Each pattern has a base confidence that reflects how much structure it can anchor on:

| Kind | Example | Base |
|---|---|---|
| Prefix-anchored | `AKIA…`, `sk_live_…` | ~0.95 |
| Structural | PEM blocks, connection strings | ~0.90 |
| Format-only | generic API keys, high-entropy strings | ~0.60 |

Then:

- **+0.02** per related keyword near the match (each pattern has its own list, such as `aws` or `secret`), up to **+0.10**.
- **−0.50** when a generic pattern's match has low Shannon entropy.
- Known documentation and test values (like `AKIAIOSFODNN7EXAMPLE`) drop to **0.15** and are flagged `is_likely_test_value`.
- Everything is clamped to **[0.05, 0.99]**.

A known-junk wordlist filters common false positives, and base64-encoded payloads are decoded and scanned too.

## Run from source

Requires Python 3.12+.

```bash
git clone https://github.com/ClassiFinder/classifinder.git
cd classifinder
pip install -r requirements.lock
CLASSIFINDER_API_KEYS=dev-key uvicorn app.main:app --reload --port 8000
```

```bash
python -m pytest tests/ -q     # full suite
ruff check .                   # lint
mypy app/                      # type check
```

[Turso](https://turso.tech) is optional and only used by the hosted service for key provisioning and feedback storage (`TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`). Without it, auth falls back to `CLASSIFINDER_API_KEYS` and feedback goes to stdout.

## Repository layout

```
app/
├── engine/          # Scanner core — pure functions, no I/O (mirrors classifinder-engine)
│   ├── scanner.py   #   scan(text) -> findings: matching, scoring, dedup
│   ├── redactor.py  #   redact(text, findings, style)
│   ├── entropy.py   #   Shannon entropy
│   ├── decoders.py  #   base64 pre-scan decoding
│   ├── false_positives.py
│   └── patterns/    #   registry + one module per category, incl. prompt_injection.py
├── routes/          # FastAPI handlers: scan, redact, types, health, feedback, keys
├── models/          # Pydantic v2 request/response models
├── middleware/      # Auth (X-API-Key) → rate limit (in-memory) → metadata-only logging
├── config.py        # All settings, from environment variables
└── main.py          # App factory, CORS, middleware wiring, JSON error handlers
scripts/             # Engine-sync check, pattern provenance check, ReDoS audit
tests/               # pytest + FastAPI TestClient
Dockerfile           # Hosted deployment (Fly.io)
Dockerfile.selfhost  # Public GHCR image
```

## Ecosystem

| Project | What it is |
|---|---|
| [`classifinder-engine`](https://github.com/ClassiFinder/classifinder-engine) | The scanner as a standalone, zero-dependency Python package |
| [`classifinder`](https://pypi.org/project/classifinder/) (SDK) | Python client, sync + async, with a LangChain guard |
| [`classifinder-mcp`](https://pypi.org/project/classifinder-mcp/) | MCP server that gives AI agents `classifinder_scan` and `classifinder_redact` tools |
| [`cfsniff`](https://github.com/ClassiFinder/cfsniff) | CLI that sniffs shell history, configs, cloud credentials, and logs for secrets |

The SDK, MCP server, and cfsniff all honour `CLASSIFINDER_BASE_URL`, so you can point them at a self-hosted instance.

## Contributing

Issues and pull requests are welcome. False positives and missed secrets are the most useful reports — the `/v1/feedback` endpoint works too.

When adding or changing a detection pattern:

- **Cite where the format comes from.** Every `re.compile()` in `app/engine/patterns/` needs a source comment (vendor docs, the vendor's own source code, or an MIT/Apache-licensed detector) within five lines above it; [`scripts/check_pattern_provenance.py`](./scripts/check_pattern_provenance.py) enforces this. Code from AGPL-licensed scanners can't be used. Credit sources in [ATTRIBUTION.md](./ATTRIBUTION.md).
- **Keep fixtures synthetic.** Never commit a real credential, even a revoked one. Build test values from fragments so no complete key literal sits in the source.
- **Add tests** in `tests/pattern_test_cases.py` (positives and negatives) and run the full suite.
- **Keep the engines in sync.** `app/engine/` must match [`classifinder-engine`](https://github.com/ClassiFinder/classifinder-engine). Clone both side by side (`classifinder/` and `classifinder-engine/` in the same parent folder), make the same change in each, and run `scripts/check_engine_sync.sh` before opening a PR.

## Security

If you've found a vulnerability — especially anything that could cause secret values to be logged, stored, or returned — please email **support@classifinder.ai** rather than opening a public issue.

## License

[MIT](./LICENSE). Third-party notices and per-pattern provenance are in [ATTRIBUTION.md](./ATTRIBUTION.md). Prompt-injection technique IDs are from the SAFE-MCP catalog (CC-BY-4.0).
