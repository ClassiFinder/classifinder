# ClassiFinder Python SDK — Design Spec

**Date:** 2026-03-23
**Status:** Approved
**Repo:** `ClassiFinder/classifinder-sdk/`

---

## Overview

A Python SDK that wraps the ClassiFinder API, published to PyPI as `pip install classifinder`. Provides typed sync and async clients for scanning and redacting secrets, plus an optional LangChain integration for AI pipeline middleware.

---

## Decisions

| Decision | Choice |
|----------|--------|
| Repo location | `ClassiFinder/classifinder-sdk/` (separate from server) |
| Sync/async | Both — `ClassiFinder` (sync) and `AsyncClassiFinder` (async) |
| Error handling | Raise exceptions with a class hierarchy |
| Retries | Built-in, on by default (`max_retries=2`), configurable |
| LangChain coupling | Optional extra: `pip install classifinder[langchain]` |
| LangChain behavior | Configurable — `mode="redact"` (default) or `mode="block"` |
| Default base URL | `https://api.classifinder.tech` |
| HTTP library | `httpx` (sync + async native support) |
| Python version | 3.10+ |
| Initial version | 0.1.0 |

---

## Package Structure

```
classifinder-sdk/
├── src/
│   └── classifinder/
│       ├── __init__.py              # Exports: ClassiFinder, AsyncClassiFinder, exceptions
│       ├── _client.py               # Sync client
│       ├── _async_client.py         # Async client
│       ├── _base.py                 # Shared: request building, response parsing, retry logic
│       ├── _exceptions.py           # Exception hierarchy
│       ├── _models.py               # Response dataclasses (Finding, ScanResult, etc.)
│       └── integrations/
│           ├── __init__.py
│           └── langchain.py         # ClassiFinderGuard Runnable
├── tests/
│   ├── test_client.py
│   ├── test_async_client.py
│   ├── test_retry.py
│   ├── test_exceptions.py
│   └── test_langchain.py
├── pyproject.toml
├── README.md
└── LICENSE
```

Underscore-prefixed files are internal. The public API is exported from `__init__.py`.

The `integrations/langchain.py` module imports `langchain-core` at runtime. If it's not installed, the import raises a clear error directing the user to `pip install classifinder[langchain]`.

---

## Client API

### Construction

```python
from classifinder import ClassiFinder, AsyncClassiFinder

# Sync
client = ClassiFinder(
    api_key="ss_live_...",                          # Required (or CLASSIFINDER_API_KEY env var)
    base_url="https://api.classifinder.tech",       # Default
    max_retries=2,                                  # Default 2, set 0 to disable
    timeout=30.0,                                   # Seconds
)

# Async
client = AsyncClassiFinder(api_key="ss_live_...")
```

If `api_key` is not passed, the client checks the `CLASSIFINDER_API_KEY` environment variable. If neither is set, raises `AuthenticationError` immediately.

### Resource Cleanup

Both clients hold HTTP connection pools that should be closed when done. They support the context manager protocol and an explicit `close()` method:

```python
# Context manager (recommended)
with ClassiFinder(api_key="...") as client:
    result = client.scan("...")

async with AsyncClassiFinder(api_key="...") as client:
    result = await client.scan("...")

# Explicit close
client = ClassiFinder(api_key="...")
try:
    result = client.scan("...")
finally:
    client.close()       # or: await client.close() for async
```

### Methods

Both clients expose identical methods:

```python
# Scan text for secrets
result = client.scan(
    text: str,                       # Required
    types: List[str] = ["all"],      # Optional filter
    min_confidence: float = 0.5,     # Optional threshold
    include_context: bool = True,    # Optional
) -> ScanResult

# Redact secrets from text
result = client.redact(
    text: str,                       # Required
    types: List[str] = ["all"],      # Optional filter
    min_confidence: float = 0.5,     # Optional threshold
    redaction_style: str = "label",  # "label", "mask", or "hash"
) -> RedactResult

# List detectable secret types
result = client.get_types() -> TypesResult

# Health check
result = client.health() -> HealthResult

# Report false positive/negative
result = client.feedback(
    request_id: str,                 # Required — from a previous scan/redact response
    finding_id: str,                 # Required — the specific finding
    feedback_type: str,              # "false_positive" or "false_negative"
    comment: Optional[str] = None,   # Optional context
) -> FeedbackResult
```

Async client methods are awaitable: `result = await client.scan(...)`.

---

## Response Models

Typed Python objects mirroring the API's JSON structure. Pydantic v2 models.

### ScanResult

```python
result.request_id: str
result.scan_time_ms: int
result.findings_count: int
result.findings: List[Finding]
result.summary: SeveritySummary
```

### Finding

```python
finding.id: str
finding.type: str
finding.type_name: str
finding.provider: str
finding.severity: str
finding.confidence: float
finding.value_preview: str
finding.span: Span              # span.start, span.end
finding.context: Optional[str]
finding.is_likely_test_value: bool
finding.recommendation: str
finding.matched_pattern: str
```

### RedactResult

```python
result.request_id: str
result.scan_time_ms: int
result.findings_count: int
result.redacted_text: str
result.findings: List[RedactFinding]
result.summary: SeveritySummary
```

### RedactFinding

```python
finding.id: str
finding.type: str
finding.severity: str
finding.confidence: float
finding.span: Span
finding.redacted_as: str
```

### TypesResult

```python
result.types_count: int
result.types: List[TypeInfo]    # id, name, provider, severity, description, tags
```

### HealthResult

```python
result.status: str
result.version: str
result.patterns_loaded: int
result.uptime_seconds: int
```

### SeveritySummary

```python
summary.critical: int
summary.high: int
summary.medium: int
summary.low: int
```

### Span

```python
span.start: int
span.end: int
```

### FeedbackResult

```python
result.feedback_id: str
result.status: str              # "received"
```

### Naming Convention

SDK models use the `*Result` suffix (e.g. `ScanResult`) to distinguish from the server's `*Response` models (e.g. `ScanResponse`). Field names and types are identical.

### Forward Compatibility

All SDK response models use `extra="ignore"` in their Pydantic model config. This ensures that when the API adds new fields to responses, existing SDK versions continue to work without breaking.

---

## Exception Hierarchy

```
ClassiFinderError (base)
├── AuthenticationError          # 401
├── RateLimitError               # 429 — has retry_after: int attribute
├── InvalidRequestError          # 400 — has code: str attribute (e.g. "payload_too_large")
├── ForbiddenError               # 403 — tier_limit_exceeded
├── ServerError                  # 500
└── APIConnectionError           # Network failure, timeout, DNS resolution failure
```

Note: `APIConnectionError` is named to avoid shadowing Python's built-in `ConnectionError`.

All exceptions carry:
- `message: str` — Human-readable error description
- `status_code: Optional[int]` — HTTP status (None for APIConnectionError)

Additional attributes on specific exceptions:
- `RateLimitError.retry_after: int` — Seconds to wait
- `InvalidRequestError.code: str` — Error code from the API (e.g. "payload_too_large", "invalid_request")
- `ForbiddenError.code: str` — Error code (e.g. "tier_limit_exceeded")

---

## Retry Logic

Built-in, enabled by default with `max_retries=2` (up to 3 total attempts).

| Error | Retried? | Strategy |
|-------|----------|----------|
| 429 Rate Limit | Yes | Wait `retry_after` seconds, then retry |
| 500 Server Error | Yes | Exponential backoff: 1s on first retry, 2s on second retry |
| Network failure / timeout | Yes | Exponential backoff: 1s on first retry, 2s on second retry |
| 401 Authentication | Never | Fails immediately |
| 400 Bad Request | Never | Fails immediately |
| 403 Forbidden | Never | Fails immediately |

After exhausting retries, raises the exception. Set `max_retries=0` to disable.

---

## LangChain Integration

### ClassiFinderGuard

A LangChain `Runnable[str, str]` that sits between the prompt and the LLM in a chain. It accepts a `str` input and returns a `str` output.

When used after a prompt template (which outputs a `PromptValue`, not a `str`), the guard calls `.to_string()` on the input to extract the text, processes it, and returns a `str`. This means the guard should be placed after any prompt formatting is complete.

```python
from classifinder.integrations.langchain import ClassiFinderGuard

guard = ClassiFinderGuard(
    api_key="ss_live_...",          # Required (or CLASSIFINDER_API_KEY env var)
    mode="redact",                  # "redact" (default) or "block"
    redaction_style="label",        # "label", "mask", or "hash" (redact mode only)
    types=["all"],                  # Secret types to check
    min_confidence=0.5,             # Confidence threshold
    base_url="https://...",         # Override API URL
)
```

### Redact Mode (default)

```python
chain = prompt | guard | llm | output_parser
result = chain.invoke({"input": user_message})
```

The guard calls `/v1/redact`, replaces the text with `redacted_text`, and passes it downstream. The chain continues with clean text. The LLM never sees real secrets.

### Block Mode

```python
guard = ClassiFinderGuard(api_key="...", mode="block", min_confidence=0.8)
chain = prompt | guard | llm | output_parser

try:
    result = chain.invoke({"input": user_message})
except SecretsDetectedError as e:
    e.findings_count: int
    e.findings: List[Finding]
    e.summary: SeveritySummary
```

The guard calls `/v1/scan`. If secrets are found, raises `SecretsDetectedError` and the chain halts. If clean, passes the text through unmodified.

### Async Support

Works with both `chain.invoke()` and `await chain.ainvoke()`. Internally uses `ClassiFinder` for sync calls and `AsyncClassiFinder` for async calls. Both clients are created lazily — the sync httpx client is created on first `invoke()` call, and the async httpx client is created on first `ainvoke()` call. This avoids creating unused clients and avoids event-loop issues with eager async client construction.

### SecretsDetectedError

```
SecretsDetectedError (extends ClassiFinderError)
├── findings_count: int
├── findings: List[Finding]
└── summary: SeveritySummary
```

Raised only in block mode when secrets are found above the confidence threshold.

---

## Dependencies

### Core (`pip install classifinder`)

| Package | Version | Purpose |
|---------|---------|---------|
| `httpx` | >=0.27.0 | HTTP client (sync + async) |
| `pydantic` | >=2.7.0 | Typed response models |

### Optional (`pip install classifinder[langchain]`)

| Package | Version | Purpose |
|---------|---------|---------|
| `langchain-core` | >=0.3.0 | Runnable base class and chain interfaces |

### Python Version

>=3.10

---

## Testing

All tests use mocked HTTP responses (httpx transport mocking). No live API calls in CI.

| Test file | Coverage |
|-----------|----------|
| `test_client.py` | Sync client: all five methods return correct typed responses. Request headers include API key. Request bodies match expected format. Base URL used correctly. Env var fallback for API key. Context manager and `close()` work correctly. |
| `test_async_client.py` | Same as sync, with `await` and `async with`. |
| `test_exceptions.py` | Mock 401 → AuthenticationError, 400 → InvalidRequestError, 403 → ForbiddenError, 429 → RateLimitError (with retry_after), 500 → ServerError. Network timeout → APIConnectionError. Verify attributes on each. |
| `test_retry.py` | 429 then 200 → retries and succeeds. Three 500s → exhausts retries, raises. 401 → no retry. 403 → no retry. `max_retries=0` → no retry. Timeout → retries with backoff. |
| `test_langchain.py` | Redact mode: secrets replaced, chain continues. Block mode: secrets found → SecretsDetectedError. Block mode: clean text → passes through. PromptValue input converted via `.to_string()`. Both sync and async invocation. Lazy client creation verified. |

One optional integration test (skipped by default, run with `--integration` flag) hits the live API to smoke-test before releases.

---

## pyproject.toml

```toml
[project]
name = "classifinder"
version = "0.1.0"
description = "Python SDK for the ClassiFinder secret detection API"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
dependencies = [
    "httpx>=0.27.0",
    "pydantic>=2.7.0",
]

[project.optional-dependencies]
langchain = ["langchain-core>=0.3.0"]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
    "respx>=0.22.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/classifinder"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

`respx` is an httpx-native mocking library for tests. `pytest-asyncio` handles async test functions.
