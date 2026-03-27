# ClassiFinder Python SDK — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python SDK (`pip install classifinder`) that wraps the ClassiFinder API with typed sync/async clients, retry logic, and a LangChain integration.

**Architecture:** Two client classes (sync `ClassiFinder`, async `AsyncClassiFinder`) sharing a common base for request building, response parsing, and retry logic. Pydantic v2 response models. Exception hierarchy mapping HTTP status codes. Optional LangChain `Runnable` guard.

**Tech Stack:** Python 3.10+, httpx, Pydantic v2, langchain-core (optional), pytest + respx + pytest-asyncio

**Spec:** `docs/specs/2026-03-23-python-sdk-design.md`

**Repo:** `ClassiFinder/classifinder-sdk/` (new, separate from server)

---

## File Structure

```
classifinder-sdk/
├── src/
│   └── classifinder/
│       ├── __init__.py              # Public API exports
│       ├── _exceptions.py           # Exception hierarchy
│       ├── _models.py               # Pydantic response models
│       ├── _base.py                 # Shared request/response/retry logic
│       ├── _client.py               # Sync client (ClassiFinder)
│       ├── _async_client.py         # Async client (AsyncClassiFinder)
│       └── integrations/
│           ├── __init__.py          # Empty
│           └── langchain.py         # ClassiFinderGuard + SecretsDetectedError
├── tests/
│   ├── conftest.py                  # Shared fixtures (mock responses, API key)
│   ├── test_exceptions.py
│   ├── test_models.py
│   ├── test_client.py
│   ├── test_async_client.py
│   ├── test_retry.py
│   └── test_langchain.py
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Task 1: Scaffold project and install dependencies

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `LICENSE`
- Create: `src/classifinder/__init__.py`
- Create: `src/classifinder/integrations/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create the repo directory**

```bash
mkdir -p /Users/thomasparas/Documents/ClassiFinder/classifinder-sdk
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-sdk
git init
```

- [ ] **Step 2: Create pyproject.toml**

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

- [ ] **Step 3: Create README.md**

Minimal README with package name, one-liner description, and install command. Full README comes later.

- [ ] **Step 4: Create LICENSE**

MIT license with current year and "ClassiFinder" as the project name.

- [ ] **Step 5: Create empty package files**

Create `src/classifinder/__init__.py` (empty for now — exports added as we build each module).

Create `src/classifinder/integrations/__init__.py` (empty).

Create `tests/conftest.py` with shared test constants:

```python
"""Shared test fixtures and constants."""

import pytest

TEST_API_KEY = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
TEST_BASE_URL = "https://api.classifinder.tech"

SCAN_RESPONSE_JSON = {
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

REDACT_RESPONSE_JSON = {
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

TYPES_RESPONSE_JSON = {
    "types_count": 1,
    "types": [
        {
            "id": "aws_access_key",
            "name": "AWS Access Key ID",
            "provider": "aws",
            "severity": "critical",
            "description": "AWS IAM access key.",
            "tags": ["cloud", "aws"],
        }
    ],
}

HEALTH_RESPONSE_JSON = {
    "status": "healthy",
    "version": "1.0.0",
    "patterns_loaded": 46,
    "uptime_seconds": 3600,
}

FEEDBACK_RESPONSE_JSON = {
    "feedback_id": "fb_abc123",
    "status": "received",
}

ERROR_401_JSON = {
    "error": {
        "code": "invalid_api_key",
        "message": "Missing, malformed, or revoked API key.",
        "retry_after": None,
    }
}

ERROR_400_JSON = {
    "error": {
        "code": "payload_too_large",
        "message": "Text size exceeds the limit.",
        "retry_after": None,
    }
}

ERROR_403_JSON = {
    "error": {
        "code": "tier_limit_exceeded",
        "message": "Feature not available on current tier.",
        "retry_after": None,
    }
}

ERROR_429_JSON = {
    "error": {
        "code": "rate_limit_exceeded",
        "message": "Rate limit exceeded.",
        "retry_after": 30,
    }
}

ERROR_500_JSON = {
    "error": {
        "code": "internal_error",
        "message": "An unexpected error occurred.",
        "retry_after": None,
    }
}
```

- [ ] **Step 6: Install in development mode and verify**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-sdk
pip install -e ".[dev]"
python -c "import classifinder; print('OK')"
pytest --co  # collect tests (should find 0 since no test files with tests yet)
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "scaffold: project structure, pyproject.toml, test fixtures"
```

---

## Task 2: Exceptions

**Files:**
- Create: `src/classifinder/_exceptions.py`
- Create: `tests/test_exceptions.py`

- [ ] **Step 1: Write tests for exception hierarchy**

`tests/test_exceptions.py`:

```python
"""Tests for the exception hierarchy."""

from classifinder._exceptions import (
    ClassiFinderError,
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
    ForbiddenError,
    ServerError,
    APIConnectionError,
    SecretsDetectedError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_base(self):
        for exc_class in (
            AuthenticationError,
            RateLimitError,
            InvalidRequestError,
            ForbiddenError,
            ServerError,
            APIConnectionError,
        ):
            assert issubclass(exc_class, ClassiFinderError)

    def test_base_has_message_and_status(self):
        e = ClassiFinderError("something broke", status_code=500)
        assert e.message == "something broke"
        assert e.status_code == 500
        assert str(e) == "something broke"

    def test_authentication_error(self):
        e = AuthenticationError("bad key")
        assert e.status_code == 401
        assert e.message == "bad key"

    def test_rate_limit_error(self):
        e = RateLimitError("too fast", retry_after=30)
        assert e.status_code == 429
        assert e.retry_after == 30

    def test_invalid_request_error(self):
        e = InvalidRequestError("too big", code="payload_too_large")
        assert e.status_code == 400
        assert e.code == "payload_too_large"

    def test_forbidden_error(self):
        e = ForbiddenError("upgrade needed", code="tier_limit_exceeded")
        assert e.status_code == 403
        assert e.code == "tier_limit_exceeded"

    def test_server_error(self):
        e = ServerError("internal error")
        assert e.status_code == 500

    def test_api_connection_error(self):
        e = APIConnectionError("timeout")
        assert e.status_code is None
        assert e.message == "timeout"

    def test_secrets_detected_error(self):
        e = SecretsDetectedError(
            "Found 2 secrets", findings_count=2, findings=["f1", "f2"], summary={"critical": 1}
        )
        assert isinstance(e, ClassiFinderError)
        assert e.findings_count == 2
        assert e.findings == ["f1", "f2"]
        assert e.summary == {"critical": 1}
        assert e.status_code is None
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_exceptions.py -v
```

Expected: ImportError — module does not exist yet.

- [ ] **Step 3: Implement exceptions**

`src/classifinder/_exceptions.py`:

```python
"""ClassiFinder SDK exception hierarchy."""

from typing import Any, Optional


class ClassiFinderError(Exception):
    """Base exception for all ClassiFinder SDK errors."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class AuthenticationError(ClassiFinderError):
    """401 — Invalid or missing API key."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=401)


class RateLimitError(ClassiFinderError):
    """429 — Rate limit exceeded."""

    def __init__(self, message: str, retry_after: int = 0) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=429)


class InvalidRequestError(ClassiFinderError):
    """400 — Bad request (malformed input, payload too large, etc.)."""

    def __init__(self, message: str, code: str = "invalid_request") -> None:
        self.code = code
        super().__init__(message, status_code=400)


class ForbiddenError(ClassiFinderError):
    """403 — Feature not available on current tier."""

    def __init__(self, message: str, code: str = "tier_limit_exceeded") -> None:
        self.code = code
        super().__init__(message, status_code=403)


class ServerError(ClassiFinderError):
    """500 — Unexpected server-side error."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=500)


class APIConnectionError(ClassiFinderError):
    """Network failure, timeout, or DNS resolution failure."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=None)


class SecretsDetectedError(ClassiFinderError):
    """Raised by ClassiFinderGuard in block mode when secrets are found."""

    def __init__(self, message: str, findings_count: int, findings: Any, summary: Any) -> None:
        self.findings_count = findings_count
        self.findings = findings  # List[Finding] at runtime
        self.summary = summary    # SeveritySummary at runtime
        super().__init__(message, status_code=None)
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_exceptions.py -v
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/classifinder/_exceptions.py tests/test_exceptions.py
git commit -m "feat: exception hierarchy with all API error codes"
```

---

## Task 3: Response models

**Files:**
- Create: `src/classifinder/_models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write tests for response models**

`tests/test_models.py`:

```python
"""Tests for Pydantic response models."""

from conftest import (
    SCAN_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
    TYPES_RESPONSE_JSON,
    HEALTH_RESPONSE_JSON,
    FEEDBACK_RESPONSE_JSON,
)
from classifinder._models import (
    ScanResult,
    RedactResult,
    TypesResult,
    HealthResult,
    FeedbackResult,
    Finding,
    RedactFinding,
)


class TestScanResult:
    def test_parse_from_json(self):
        result = ScanResult.model_validate(SCAN_RESPONSE_JSON)
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.scan_time_ms == 7
        assert result.findings_count == 1
        assert len(result.findings) == 1
        assert result.summary.critical == 1

    def test_finding_fields(self):
        result = ScanResult.model_validate(SCAN_RESPONSE_JSON)
        f = result.findings[0]
        assert f.type == "aws_access_key"
        assert f.type_name == "AWS Access Key ID"
        assert f.provider == "aws"
        assert f.severity == "critical"
        assert f.confidence == 0.98
        assert f.value_preview == "AKIA****MPLE"
        assert f.span.start == 22
        assert f.span.end == 42
        assert f.is_likely_test_value is False

    def test_ignores_extra_fields(self):
        data = {**SCAN_RESPONSE_JSON, "new_future_field": "ignored"}
        result = ScanResult.model_validate(data)
        assert result.request_id == "req_a1b2c3d4e5f6"


class TestRedactResult:
    def test_parse_from_json(self):
        result = RedactResult.model_validate(REDACT_RESPONSE_JSON)
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"
        assert result.findings_count == 1
        assert result.findings[0].redacted_as == "[AWS_ACCESS_KEY_REDACTED]"

    def test_redact_finding_fields(self):
        result = RedactResult.model_validate(REDACT_RESPONSE_JSON)
        f = result.findings[0]
        assert f.type == "aws_access_key"
        assert f.severity == "critical"
        assert f.span.start == 22


class TestTypesResult:
    def test_parse_from_json(self):
        result = TypesResult.model_validate(TYPES_RESPONSE_JSON)
        assert result.types_count == 1
        assert result.types[0].id == "aws_access_key"
        assert result.types[0].tags == ["cloud", "aws"]


class TestHealthResult:
    def test_parse_from_json(self):
        result = HealthResult.model_validate(HEALTH_RESPONSE_JSON)
        assert result.status == "healthy"
        assert result.patterns_loaded == 46


class TestFeedbackResult:
    def test_parse_from_json(self):
        result = FeedbackResult.model_validate(FEEDBACK_RESPONSE_JSON)
        assert result.feedback_id == "fb_abc123"
        assert result.status == "received"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_models.py -v
```

- [ ] **Step 3: Implement response models**

`src/classifinder/_models.py`:

```python
"""Pydantic v2 response models for the ClassiFinder API."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Span(_Base):
    start: int
    end: int


class SeveritySummary(_Base):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Finding(_Base):
    id: str
    type: str
    type_name: str
    provider: str
    severity: str
    confidence: float
    value_preview: str
    span: Span
    context: Optional[str] = None
    is_likely_test_value: bool
    recommendation: str
    matched_pattern: str


class RedactFinding(_Base):
    id: str
    type: str
    severity: str
    confidence: float
    span: Span
    redacted_as: str


class TypeInfo(_Base):
    id: str
    name: str
    provider: str
    severity: str
    description: str
    tags: List[str] = []


class ScanResult(_Base):
    request_id: str
    scan_time_ms: int
    findings_count: int
    findings: List[Finding]
    summary: SeveritySummary


class RedactResult(_Base):
    request_id: str
    scan_time_ms: int
    findings_count: int
    redacted_text: str
    findings: List[RedactFinding]
    summary: SeveritySummary


class TypesResult(_Base):
    types_count: int
    types: List[TypeInfo]


class HealthResult(_Base):
    status: str
    version: str
    patterns_loaded: int
    uptime_seconds: int


class FeedbackResult(_Base):
    feedback_id: str
    status: str
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_models.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/classifinder/_models.py tests/test_models.py
git commit -m "feat: Pydantic response models with forward compatibility"
```

---

## Task 4: Base client logic (shared request/response/retry)

**Files:**
- Create: `src/classifinder/_base.py`

No dedicated test file — this module is tested indirectly through the sync/async client tests. It contains:

1. A helper that maps HTTP error responses to the correct exception class
2. Request body builders for each endpoint
3. Retry logic with exponential backoff

- [ ] **Step 1: Implement the base module**

`src/classifinder/_base.py`:

```python
"""Shared logic for sync and async clients: error mapping, retry, request building."""

import os
import time
from typing import Any, Dict, Optional

import httpx

from ._exceptions import (
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
    ForbiddenError,
    ServerError,
    APIConnectionError,
    ClassiFinderError,
)

DEFAULT_BASE_URL = "https://api.classifinder.tech"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2

# Status codes that are safe to retry
_RETRYABLE_STATUS_CODES = {429, 500}


def resolve_api_key(api_key: Optional[str]) -> str:
    """Resolve API key from argument or CLASSIFINDER_API_KEY env var."""
    key = api_key or os.environ.get("CLASSIFINDER_API_KEY")
    if not key:
        raise AuthenticationError(
            "No API key provided. Pass api_key= or set the CLASSIFINDER_API_KEY environment variable."
        )
    return key


def build_headers(api_key: str) -> Dict[str, str]:
    """Build default request headers."""
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }


def raise_for_status(response: httpx.Response) -> None:
    """Raise the appropriate ClassiFinderError for non-2xx responses."""
    if response.status_code < 400:
        return

    try:
        body = response.json()
        error = body.get("error", {})
        message = error.get("message", response.text)
        code = error.get("code", "")
        retry_after = error.get("retry_after")
    except Exception:
        message = response.text or f"HTTP {response.status_code}"
        code = ""
        retry_after = None

    status = response.status_code

    if status == 401:
        raise AuthenticationError(message)
    elif status == 400:
        raise InvalidRequestError(message, code=code)
    elif status == 403:
        raise ForbiddenError(message, code=code)
    elif status == 429:
        raise RateLimitError(message, retry_after=retry_after or 0)
    elif status >= 500:
        raise ServerError(message)
    else:
        raise ClassiFinderError(message, status_code=status)


def is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable."""
    if isinstance(exc, RateLimitError):
        return True
    if isinstance(exc, ServerError):
        return True
    if isinstance(exc, APIConnectionError):
        return True
    return False


def get_retry_delay(attempt: int, exc: Exception) -> float:
    """Calculate delay before next retry attempt.

    Args:
        attempt: 0-indexed retry attempt number (0 = first retry).
        exc: The exception that triggered the retry.
    """
    if isinstance(exc, RateLimitError) and exc.retry_after > 0:
        return float(exc.retry_after)
    # Exponential backoff: 1s, 2s, 4s, ...
    return float(2**attempt)


def sleep_for_retry(attempt: int, exc: Exception) -> None:
    """Sleep before a sync retry."""
    delay = get_retry_delay(attempt, exc)
    time.sleep(delay)


async def async_sleep_for_retry(attempt: int, exc: Exception) -> None:
    """Sleep before an async retry."""
    import asyncio

    delay = get_retry_delay(attempt, exc)
    await asyncio.sleep(delay)
```

- [ ] **Step 2: Commit**

```bash
git add src/classifinder/_base.py
git commit -m "feat: shared base logic — error mapping, retry helpers, request building"
```

---

## Task 5: Sync client

**Files:**
- Create: `src/classifinder/_client.py`
- Create: `tests/test_client.py`

- [ ] **Step 1: Write sync client tests**

`tests/test_client.py`:

```python
"""Tests for the synchronous ClassiFinder client."""

import os

import httpx
import pytest
import respx

from conftest import (
    TEST_API_KEY,
    TEST_BASE_URL,
    SCAN_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
    TYPES_RESPONSE_JSON,
    HEALTH_RESPONSE_JSON,
    FEEDBACK_RESPONSE_JSON,
)
from classifinder._client import ClassiFinder
from classifinder._exceptions import AuthenticationError


class TestClientConstruction:
    def test_requires_api_key(self):
        with pytest.raises(AuthenticationError, match="No API key"):
            ClassiFinder()

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("CLASSIFINDER_API_KEY", TEST_API_KEY)
        client = ClassiFinder()
        assert client._api_key == TEST_API_KEY
        client.close()

    def test_custom_base_url(self):
        client = ClassiFinder(api_key=TEST_API_KEY, base_url="https://custom.example.com")
        assert client._base_url == "https://custom.example.com"
        client.close()

    def test_context_manager(self):
        with ClassiFinder(api_key=TEST_API_KEY) as client:
            assert client._api_key == TEST_API_KEY


@respx.mock
class TestScan:
    def test_scan_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.scan("some text with secrets")
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.findings_count == 1
        assert result.findings[0].type == "aws_access_key"

    def test_scan_sends_correct_body(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.scan("test text", types=["aws_access_key"], min_confidence=0.8, include_context=False)
        body = route.calls[0].request.content
        import json
        parsed = json.loads(body)
        assert parsed["text"] == "test text"
        assert parsed["types"] == ["aws_access_key"]
        assert parsed["min_confidence"] == 0.8
        assert parsed["include_context"] is False

    def test_scan_sends_api_key_header(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.scan("text")
        assert route.calls[0].request.headers["X-API-Key"] == TEST_API_KEY


@respx.mock
class TestRedact:
    def test_redact_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.redact("secret text")
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"
        assert result.findings[0].redacted_as == "[AWS_ACCESS_KEY_REDACTED]"

    def test_redact_sends_style(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.redact("text", redaction_style="mask")
        import json
        parsed = json.loads(route.calls[0].request.content)
        assert parsed["redaction_style"] == "mask"


@respx.mock
class TestGetTypes:
    def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/types").mock(
            return_value=httpx.Response(200, json=TYPES_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.get_types()
        assert result.types_count == 1
        assert result.types[0].id == "aws_access_key"


@respx.mock
class TestHealth:
    def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/health").mock(
            return_value=httpx.Response(200, json=HEALTH_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.health()
        assert result.status == "healthy"
        assert result.patterns_loaded == 46


@respx.mock
class TestFeedback:
    def test_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/feedback").mock(
            return_value=httpx.Response(202, json=FEEDBACK_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.feedback(
                request_id="req_abc", finding_id="f_001", feedback_type="false_positive"
            )
        assert result.feedback_id == "fb_abc123"
        assert result.status == "received"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_client.py -v
```

- [ ] **Step 3: Implement sync client**

`src/classifinder/_client.py`:

```python
"""Synchronous ClassiFinder client."""

from typing import List, Optional

import httpx

from ._base import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    build_headers,
    is_retryable,
    raise_for_status,
    resolve_api_key,
    sleep_for_retry,
)
from ._exceptions import APIConnectionError
from ._models import (
    FeedbackResult,
    HealthResult,
    RedactResult,
    ScanResult,
    TypesResult,
)


class ClassiFinder:
    """Synchronous client for the ClassiFinder API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = resolve_api_key(api_key)
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._client = httpx.Client(
            headers=build_headers(self._api_key),
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> "ClassiFinder":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an HTTP request with retry logic."""
        url = f"{self._base_url}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(method, url, **kwargs)
                raise_for_status(response)
                return response
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                api_exc = APIConnectionError(str(exc))
                last_exc = api_exc
                if attempt >= self._max_retries:
                    raise api_exc from exc
                sleep_for_retry(attempt, api_exc)
            except Exception as exc:
                last_exc = exc
                if not is_retryable(exc) or attempt >= self._max_retries:
                    raise
                sleep_for_retry(attempt, exc)

        raise last_exc  # pragma: no cover

    def scan(
        self,
        text: str,
        types: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        include_context: bool = True,
    ) -> ScanResult:
        """Scan text for secrets."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "include_context": include_context,
        }
        response = self._request("POST", "/v1/scan", json=body)
        return ScanResult.model_validate(response.json())

    def redact(
        self,
        text: str,
        types: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        redaction_style: str = "label",
    ) -> RedactResult:
        """Scan and redact secrets from text."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "redaction_style": redaction_style,
        }
        response = self._request("POST", "/v1/redact", json=body)
        return RedactResult.model_validate(response.json())

    def get_types(self) -> TypesResult:
        """List all detectable secret types."""
        response = self._request("GET", "/v1/types")
        return TypesResult.model_validate(response.json())

    def health(self) -> HealthResult:
        """Check API health."""
        response = self._request("GET", "/v1/health")
        return HealthResult.model_validate(response.json())

    def feedback(
        self,
        request_id: str,
        finding_id: str,
        feedback_type: str,
        comment: Optional[str] = None,
    ) -> FeedbackResult:
        """Report a false positive or false negative."""
        body = {
            "request_id": request_id,
            "finding_id": finding_id,
            "feedback_type": feedback_type,
        }
        if comment is not None:
            body["comment"] = comment
        response = self._request("POST", "/v1/feedback", json=body)
        return FeedbackResult.model_validate(response.json())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_client.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/classifinder/_client.py tests/test_client.py
git commit -m "feat: synchronous ClassiFinder client with all 5 methods"
```

---

## Task 6: Async client

**Files:**
- Create: `src/classifinder/_async_client.py`
- Create: `tests/test_async_client.py`

- [ ] **Step 1: Write async client tests**

`tests/test_async_client.py`:

```python
"""Tests for the asynchronous AsyncClassiFinder client."""

import httpx
import pytest
import respx

from conftest import (
    TEST_API_KEY,
    TEST_BASE_URL,
    SCAN_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
    TYPES_RESPONSE_JSON,
    HEALTH_RESPONSE_JSON,
    FEEDBACK_RESPONSE_JSON,
)
from classifinder._async_client import AsyncClassiFinder
from classifinder._exceptions import AuthenticationError


class TestAsyncConstruction:
    def test_requires_api_key(self):
        with pytest.raises(AuthenticationError, match="No API key"):
            AsyncClassiFinder()

    async def test_async_context_manager(self):
        async with AsyncClassiFinder(api_key=TEST_API_KEY) as client:
            assert client._api_key == TEST_API_KEY


@respx.mock
class TestAsyncScan:
    async def test_scan_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.scan("some text")
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.findings[0].type == "aws_access_key"


@respx.mock
class TestAsyncRedact:
    async def test_redact_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.redact("secret text")
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"


@respx.mock
class TestAsyncGetTypes:
    async def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/types").mock(
            return_value=httpx.Response(200, json=TYPES_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.get_types()
        assert result.types_count == 1


@respx.mock
class TestAsyncHealth:
    async def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/health").mock(
            return_value=httpx.Response(200, json=HEALTH_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.health()
        assert result.status == "healthy"


@respx.mock
class TestAsyncFeedback:
    async def test_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/feedback").mock(
            return_value=httpx.Response(202, json=FEEDBACK_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.feedback(
                request_id="req_abc", finding_id="f_001", feedback_type="false_positive"
            )
        assert result.feedback_id == "fb_abc123"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_async_client.py -v
```

- [ ] **Step 3: Implement async client**

`src/classifinder/_async_client.py`:

```python
"""Asynchronous ClassiFinder client."""

from typing import List, Optional

import httpx

from ._base import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    async_sleep_for_retry,
    build_headers,
    is_retryable,
    raise_for_status,
    resolve_api_key,
)
from ._exceptions import APIConnectionError
from ._models import (
    FeedbackResult,
    HealthResult,
    RedactResult,
    ScanResult,
    TypesResult,
)


class AsyncClassiFinder:
    """Asynchronous client for the ClassiFinder API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = resolve_api_key(api_key)
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._client = httpx.AsyncClient(
            headers=build_headers(self._api_key),
            timeout=timeout,
        )

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncClassiFinder":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an HTTP request with retry logic."""
        url = f"{self._base_url}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(method, url, **kwargs)
                raise_for_status(response)
                return response
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                api_exc = APIConnectionError(str(exc))
                last_exc = api_exc
                if attempt >= self._max_retries:
                    raise api_exc from exc
                await async_sleep_for_retry(attempt, api_exc)
            except Exception as exc:
                last_exc = exc
                if not is_retryable(exc) or attempt >= self._max_retries:
                    raise
                await async_sleep_for_retry(attempt, exc)

        raise last_exc  # pragma: no cover

    async def scan(
        self,
        text: str,
        types: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        include_context: bool = True,
    ) -> ScanResult:
        """Scan text for secrets."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "include_context": include_context,
        }
        response = await self._request("POST", "/v1/scan", json=body)
        return ScanResult.model_validate(response.json())

    async def redact(
        self,
        text: str,
        types: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        redaction_style: str = "label",
    ) -> RedactResult:
        """Scan and redact secrets from text."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "redaction_style": redaction_style,
        }
        response = await self._request("POST", "/v1/redact", json=body)
        return RedactResult.model_validate(response.json())

    async def get_types(self) -> TypesResult:
        """List all detectable secret types."""
        response = await self._request("GET", "/v1/types")
        return TypesResult.model_validate(response.json())

    async def health(self) -> HealthResult:
        """Check API health."""
        response = await self._request("GET", "/v1/health")
        return HealthResult.model_validate(response.json())

    async def feedback(
        self,
        request_id: str,
        finding_id: str,
        feedback_type: str,
        comment: Optional[str] = None,
    ) -> FeedbackResult:
        """Report a false positive or false negative."""
        body = {
            "request_id": request_id,
            "finding_id": finding_id,
            "feedback_type": feedback_type,
        }
        if comment is not None:
            body["comment"] = comment
        response = await self._request("POST", "/v1/feedback", json=body)
        return FeedbackResult.model_validate(response.json())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_async_client.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/classifinder/_async_client.py tests/test_async_client.py
git commit -m "feat: async ClassiFinder client with all 5 methods"
```

---

## Task 7: Error handling and retry tests

**Files:**
- Modify: `tests/test_exceptions.py` (already exists — add API error mapping tests)
- Create: `tests/test_retry.py`

- [ ] **Step 1: Write error mapping tests**

Append to `tests/test_exceptions.py`:

```python
import httpx
import respx

from conftest import (
    TEST_API_KEY,
    TEST_BASE_URL,
    ERROR_401_JSON,
    ERROR_400_JSON,
    ERROR_403_JSON,
    ERROR_429_JSON,
    ERROR_500_JSON,
)
from classifinder._client import ClassiFinder
from classifinder._exceptions import (
    AuthenticationError,
    InvalidRequestError,
    ForbiddenError,
    RateLimitError,
    ServerError,
)


@respx.mock
class TestErrorMapping:
    def test_401_raises_authentication_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(401, json=ERROR_401_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(AuthenticationError, match="Missing"):
                client.scan("text")

    def test_400_raises_invalid_request_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(400, json=ERROR_400_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(InvalidRequestError) as exc_info:
                client.scan("text")
        assert exc_info.value.code == "payload_too_large"

    def test_403_raises_forbidden_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(403, json=ERROR_403_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(ForbiddenError) as exc_info:
                client.scan("text")
        assert exc_info.value.code == "tier_limit_exceeded"

    def test_429_raises_rate_limit_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(429, json=ERROR_429_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(RateLimitError) as exc_info:
                client.scan("text")
        assert exc_info.value.retry_after == 30

    def test_500_raises_server_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(ServerError, match="unexpected"):
                client.scan("text")
```

- [ ] **Step 2: Write retry tests**

`tests/test_retry.py`:

```python
"""Tests for retry logic."""

from unittest.mock import patch

import httpx
import pytest
import respx

from conftest import TEST_API_KEY, TEST_BASE_URL, SCAN_RESPONSE_JSON, ERROR_429_JSON, ERROR_500_JSON
from classifinder._client import ClassiFinder
from classifinder._exceptions import RateLimitError, ServerError, AuthenticationError, ForbiddenError, APIConnectionError


@respx.mock
class TestRetry:
    @patch("classifinder._base.time.sleep")
    def test_retries_on_429_then_succeeds(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.Response(429, json=ERROR_429_JSON),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(30.0)

    @patch("classifinder._base.time.sleep")
    def test_retries_on_500_with_backoff(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.Response(500, json=ERROR_500_JSON),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(1.0)  # 2^0 = 1s for first retry

    @patch("classifinder._base.time.sleep")
    def test_exhausts_retries_then_raises(self, mock_sleep):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            with pytest.raises(ServerError):
                client.scan("text")
        assert mock_sleep.call_count == 2  # retried twice before giving up

    def test_no_retry_on_401(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(401, json={"error": {"code": "invalid_api_key", "message": "bad", "retry_after": None}})
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            with pytest.raises(AuthenticationError):
                client.scan("text")

    def test_no_retry_on_403(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(403, json={"error": {"code": "tier_limit_exceeded", "message": "upgrade", "retry_after": None}})
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            with pytest.raises(ForbiddenError):
                client.scan("text")

    def test_no_retry_when_disabled(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(ServerError):
                client.scan("text")

    @patch("classifinder._base.time.sleep")
    def test_retries_on_network_timeout(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.ConnectError("connection refused"),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(1.0)

    def test_network_timeout_raises_api_connection_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(side_effect=httpx.ConnectError("refused"))
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                client.scan("text")
```

- [ ] **Step 3: Run all tests**

```bash
pytest tests/test_exceptions.py tests/test_retry.py -v
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_exceptions.py tests/test_retry.py
git commit -m "test: error mapping and retry logic"
```

---

## Task 8: Public API exports (`__init__.py`)

**Files:**
- Modify: `src/classifinder/__init__.py`

- [ ] **Step 1: Wire up all exports**

`src/classifinder/__init__.py`:

```python
"""ClassiFinder Python SDK — scan and redact secrets from text."""

from ._client import ClassiFinder
from ._async_client import AsyncClassiFinder
from ._exceptions import (
    ClassiFinderError,
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
    ForbiddenError,
    ServerError,
    APIConnectionError,
    SecretsDetectedError,
)
from ._models import (
    ScanResult,
    RedactResult,
    TypesResult,
    HealthResult,
    FeedbackResult,
    Finding,
    RedactFinding,
    Span,
    SeveritySummary,
    TypeInfo,
)

__all__ = [
    "ClassiFinder",
    "AsyncClassiFinder",
    "ClassiFinderError",
    "AuthenticationError",
    "RateLimitError",
    "InvalidRequestError",
    "ForbiddenError",
    "ServerError",
    "APIConnectionError",
    "SecretsDetectedError",
    "ScanResult",
    "RedactResult",
    "TypesResult",
    "HealthResult",
    "FeedbackResult",
    "Finding",
    "RedactFinding",
    "Span",
    "SeveritySummary",
    "TypeInfo",
]
```

- [ ] **Step 2: Verify imports work from the public API**

```bash
python -c "from classifinder import ClassiFinder, AsyncClassiFinder, AuthenticationError, ScanResult; print('All imports OK')"
```

- [ ] **Step 3: Run full test suite**

```bash
pytest tests/ -v
```

All tests should pass.

- [ ] **Step 4: Commit**

```bash
git add src/classifinder/__init__.py
git commit -m "feat: wire up public API exports"
```

---

## Task 9: LangChain integration

**Files:**
- Create: `src/classifinder/integrations/langchain.py`
- Create: `tests/test_langchain.py`

- [ ] **Step 1: Write LangChain tests**

`tests/test_langchain.py`:

```python
"""Tests for the LangChain ClassiFinderGuard integration."""

import httpx
import pytest
import respx

from conftest import (
    TEST_API_KEY,
    TEST_BASE_URL,
    SCAN_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
)

# Build a clean-text scan response (no findings)
CLEAN_SCAN_JSON = {
    "request_id": "req_clean",
    "scan_time_ms": 1,
    "findings_count": 0,
    "findings": [],
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}

CLEAN_REDACT_JSON = {
    "request_id": "req_clean",
    "scan_time_ms": 1,
    "findings_count": 0,
    "redacted_text": "Hello, this is clean text.",
    "findings": [],
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}


try:
    from classifinder.integrations.langchain import ClassiFinderGuard, SecretsDetectedError

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

pytestmark = pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain-core not installed")


@respx.mock
class TestRedactMode:
    def test_redacts_and_passes_through(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke("text with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert result == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"

    def test_clean_text_passes_through(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke("Hello, this is clean text.")
        assert result == "Hello, this is clean text."


@respx.mock
class TestBlockMode:
    def test_raises_on_secrets(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        with pytest.raises(SecretsDetectedError) as exc_info:
            guard.invoke("text with secrets")
        assert exc_info.value.findings_count == 1
        assert exc_info.value.findings[0].type == "aws_access_key"

    def test_passes_clean_text(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=CLEAN_SCAN_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        result = guard.invoke("safe text")
        assert result == "safe text"


@respx.mock
class TestPromptValueInput:
    def test_coerces_prompt_value(self):
        """PromptValue objects should be converted via .to_string()."""

        class FakePromptValue:
            def to_string(self):
                return "text from prompt value"

        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke(FakePromptValue())
        assert result == "Hello, this is clean text."


class TestLazyClientCreation:
    def test_sync_client_created_lazily(self):
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL)
        assert guard._sync_client is None
        # After invoke, it should be populated
        with respx.mock:
            respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
                return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
            )
            guard.invoke("text")
        assert guard._sync_client is not None

    async def test_async_client_created_lazily(self):
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL)
        assert guard._async_client is None
        with respx.mock:
            respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
                return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
            )
            await guard.ainvoke("text")
        assert guard._async_client is not None


@respx.mock
class TestAsyncGuard:
    async def test_async_redact(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = await guard.ainvoke("text with secrets")
        assert result == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"

    async def test_async_block(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        with pytest.raises(SecretsDetectedError):
            await guard.ainvoke("text with secrets")
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pip install langchain-core  # install optional dep for testing
pytest tests/test_langchain.py -v
```

- [ ] **Step 3: Implement the LangChain guard**

`src/classifinder/integrations/langchain.py`:

```python
"""LangChain integration — ClassiFinderGuard Runnable."""

from typing import Any, List, Optional

from pydantic import ConfigDict, PrivateAttr

try:
    from langchain_core.runnables import RunnableSerializable
except ImportError:
    raise ImportError(
        "langchain-core is required for the LangChain integration. "
        "Install it with: pip install classifinder[langchain]"
    )

from .._client import ClassiFinder
from .._async_client import AsyncClassiFinder
from .._exceptions import SecretsDetectedError
from .._models import ScanResult


class ClassiFinderGuard(RunnableSerializable[str, str]):
    """A LangChain Runnable that scans/redacts secrets from text.

    In redact mode (default), secrets are replaced and the clean text is
    passed downstream. In block mode, an exception is raised if secrets
    are found.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    api_key: Optional[str] = None
    mode: str = "redact"
    redaction_style: str = "label"
    types: List[str] = ["all"]
    min_confidence: float = 0.5
    base_url: str = "https://api.classifinder.tech"
    max_retries: int = 2
    timeout: float = 30.0

    # Lazy-initialized clients (private attrs)
    _sync_client: Optional[ClassiFinder] = PrivateAttr(default=None)
    _async_client: Optional[AsyncClassiFinder] = PrivateAttr(default=None)

    def _get_sync_client(self) -> ClassiFinder:
        if self._sync_client is None:
            self._sync_client = ClassiFinder(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=self.max_retries,
                timeout=self.timeout,
            )
        return self._sync_client

    def _get_async_client(self) -> AsyncClassiFinder:
        if self._async_client is None:
            self._async_client = AsyncClassiFinder(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=self.max_retries,
                timeout=self.timeout,
            )
        return self._async_client

    def _coerce_input(self, input: Any) -> str:
        """Convert input to string, handling PromptValue objects."""
        if isinstance(input, str):
            return input
        if hasattr(input, "to_string"):
            return input.to_string()
        return str(input)

    def invoke(self, input: Any, config: Any = None, **kwargs) -> str:
        """Sync: scan/redact text and return result."""
        text = self._coerce_input(input)
        client = self._get_sync_client()

        if self.mode == "block":
            result = client.scan(
                text=text,
                types=self.types,
                min_confidence=self.min_confidence,
            )
            if result.findings_count > 0:
                raise SecretsDetectedError(
                    message=f"Found {result.findings_count} secret(s) in input text.",
                    findings_count=result.findings_count,
                    findings=result.findings,
                    summary=result.summary,
                )
            return text
        else:
            result = client.redact(
                text=text,
                types=self.types,
                min_confidence=self.min_confidence,
                redaction_style=self.redaction_style,
            )
            return result.redacted_text

    async def ainvoke(self, input: Any, config: Any = None, **kwargs) -> str:
        """Async: scan/redact text and return result."""
        text = self._coerce_input(input)
        client = self._get_async_client()

        if self.mode == "block":
            result = await client.scan(
                text=text,
                types=self.types,
                min_confidence=self.min_confidence,
            )
            if result.findings_count > 0:
                raise SecretsDetectedError(
                    message=f"Found {result.findings_count} secret(s) in input text.",
                    findings_count=result.findings_count,
                    findings=result.findings,
                    summary=result.summary,
                )
            return text
        else:
            result = await client.redact(
                text=text,
                types=self.types,
                min_confidence=self.min_confidence,
                redaction_style=self.redaction_style,
            )
            return result.redacted_text
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_langchain.py -v
```

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -v
```

All tests should pass.

- [ ] **Step 6: Commit**

```bash
git add src/classifinder/integrations/langchain.py tests/test_langchain.py
git commit -m "feat: LangChain ClassiFinderGuard with redact and block modes"
```

---

## Task 10: README and final polish

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write the PyPI-facing README**

`README.md` — include:
- Package name and one-liner
- Install command (`pip install classifinder`)
- Quick start: create client, scan, redact
- LangChain integration example (`pip install classifinder[langchain]`)
- Error handling example
- Link to API docs at `https://classifinder.tech`

- [ ] **Step 2: Run full test suite one final time**

```bash
pytest tests/ -v
```

- [ ] **Step 3: Verify package builds cleanly**

```bash
pip install build
python -m build
ls dist/  # should show .whl and .tar.gz
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: PyPI README with quickstart and examples"
```

---

## Summary

| Task | What it builds | Files |
|------|---------------|-------|
| 1 | Project scaffold | pyproject.toml, README, LICENSE, conftest.py |
| 2 | Exceptions | _exceptions.py, test_exceptions.py |
| 3 | Response models | _models.py, test_models.py |
| 4 | Shared base logic | _base.py |
| 5 | Sync client | _client.py, test_client.py |
| 6 | Async client | _async_client.py, test_async_client.py |
| 7 | Error/retry tests | test_exceptions.py (append), test_retry.py |
| 8 | Public exports | __init__.py |
| 9 | LangChain guard | integrations/langchain.py, test_langchain.py |
| 10 | README + build | README.md |
