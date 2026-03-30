# Feedback Persistence Implementation Plan

> **STATUS: COMPLETED** — Implemented 2026-03-26. Feedback persists anonymous metadata to Turso, `expected_type` field validates against pattern registry, feedback-specific rate limit (10/hour/key), CLI report script for aggregates. Subsequently revised to drop `api_key_hash` from storage for privacy. 93 tests passing. This plan is archived for historical reference.

> ~~**For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.~~

**Goal:** Make the feedback endpoint persist structured metadata to Turso, add an `expected_type` field for false negatives, and provide a CLI script for querying feedback trends.

**Architecture:** Extend the existing Turso integration (`app/key_store.py` pattern) to store feedback metadata in a `feedback` table. The feedback route gains persistence with graceful fallback to stdout when Turso is unavailable. A new `expected_type` field on `FeedbackRequest` validates against the engine's pattern registry. A standalone CLI script queries aggregated feedback data.

**Tech Stack:** Python 3.12+, FastAPI, Pydantic v2, libsql_experimental (Turso), pytest

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `app/feedback_store.py` | Create | Turso persistence for feedback: init table, insert row, query aggregates |
| `app/models/requests.py` | Modify | Add `expected_type` field to `FeedbackRequest` with registry validation |
| `app/routes/feedback.py` | Modify | Wire in persistence (Turso or stdout fallback), pass `expected_type` |
| `app/main.py` | Modify | Call `feedback_store.init_feedback_table()` in lifespan |
| `scripts/feedback_report.py` | Create | CLI tool for querying feedback aggregates |
| `tests/test_feedback.py` | Create | Dedicated test file for all new feedback functionality |
| `docs/classifinder-api-spec.md` | Modify | Document `expected_type` field |

---

### Task 1: Feedback Store — Table Init and Insert

**Files:**
- Create: `app/feedback_store.py`
- Test: `tests/test_feedback.py`

- [ ] **Step 1: Write failing test for feedback table initialization**

Create `tests/test_feedback.py`:

```python
"""
ClassiFinder — Feedback Persistence Tests

Tests feedback storage to Turso and fallback behavior.
Run with: python -m pytest tests/test_feedback.py -v
"""

import os
import pytest

os.environ.setdefault("CLASSIFINDER_API_KEYS", "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx")
os.environ.setdefault("CLASSIFINDER_RATE_LIMIT_PER_MINUTE", "1000")


class TestFeedbackStoreInit:
    def test_init_creates_feedback_table(self, tmp_path):
        """init_feedback_table creates the feedback table in a local SQLite DB."""
        import libsql_experimental as libsql

        db_path = str(tmp_path / "test.db")
        conn = libsql.connect(db_path)

        from app.feedback_store import init_feedback_table
        init_feedback_table(conn)

        # Verify table exists by inserting and selecting
        conn.execute(
            """INSERT INTO feedback
               (feedback_id, request_id, finding_id, feedback_type, has_comment, api_key_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("fb_test01", "req_abc", "f_001", "false_positive", False, "abcd1234", "2026-03-26T00:00:00Z"),
        )
        conn.commit()
        row = conn.execute("SELECT feedback_id FROM feedback WHERE feedback_id = ?", ("fb_test01",)).fetchone()
        assert row is not None
        assert row[0] == "fb_test01"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestFeedbackStoreInit::test_init_creates_feedback_table -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.feedback_store'`

- [ ] **Step 3: Write failing test for insert_feedback**

Append to `tests/test_feedback.py`:

```python
class TestInsertFeedback:
    def test_insert_feedback_stores_row(self, tmp_path):
        """insert_feedback persists a feedback record."""
        import libsql_experimental as libsql

        db_path = str(tmp_path / "test.db")
        conn = libsql.connect(db_path)

        from app.feedback_store import init_feedback_table, insert_feedback
        init_feedback_table(conn)

        insert_feedback(
            conn=conn,
            feedback_id="fb_abc123",
            request_id="req_xyz",
            finding_id="f_002",
            feedback_type="false_negative",
            has_comment=True,
            api_key_hash="deadbeef",
            expected_type="aws_access_key",
        )

        row = conn.execute("SELECT * FROM feedback WHERE feedback_id = ?", ("fb_abc123",)).fetchone()
        assert row is not None
        # Row: (feedback_id, request_id, finding_id, feedback_type, has_comment, api_key_hash, expected_type, created_at)
        assert row[0] == "fb_abc123"
        assert row[3] == "false_negative"
        assert row[4] == 1  # has_comment = True → 1 in SQLite
        assert row[6] == "aws_access_key"

    def test_insert_feedback_without_expected_type(self, tmp_path):
        """insert_feedback works when expected_type is None."""
        import libsql_experimental as libsql

        db_path = str(tmp_path / "test.db")
        conn = libsql.connect(db_path)

        from app.feedback_store import init_feedback_table, insert_feedback
        init_feedback_table(conn)

        insert_feedback(
            conn=conn,
            feedback_id="fb_def456",
            request_id="req_abc",
            finding_id="f_001",
            feedback_type="false_positive",
            has_comment=False,
            api_key_hash="cafe0000",
            expected_type=None,
        )

        row = conn.execute("SELECT expected_type FROM feedback WHERE feedback_id = ?", ("fb_def456",)).fetchone()
        assert row[0] is None
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cd classifinder && python -m pytest tests/test_feedback.py -v`
Expected: FAIL — `ImportError: cannot import name 'insert_feedback'`

- [ ] **Step 5: Implement feedback_store.py**

Create `app/feedback_store.py`:

```python
"""
ClassiFinder — Feedback Store

Persists feedback metadata to Turso (hosted SQLite). Follows the same
connection pattern as key_store.py. All functions are synchronous —
call via asyncio.to_thread() from async contexts.

Never stores comment text or secret values. Only structured metadata.
"""

import time
from typing import Optional

from app.config import get_settings

_db_conn = None


def _get_conn():
    """Get or create the Turso database connection for feedback."""
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    settings = get_settings()
    if not settings.turso_enabled:
        raise RuntimeError("Turso is not configured")
    import libsql_experimental as libsql
    _db_conn = libsql.connect(
        settings.turso_database_url,
        auth_token=settings.turso_auth_token,
    )
    return _db_conn


def reset_conn() -> None:
    """Reset the connection. Used in tests."""
    global _db_conn
    _db_conn = None


def init_feedback_table(conn=None) -> None:
    """Create the feedback table if it doesn't exist.

    Args:
        conn: Optional connection override (for testing with local SQLite).
             If None, uses the Turso connection.
    """
    if conn is None:
        settings = get_settings()
        if not settings.turso_enabled:
            return
        conn = _get_conn()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            feedback_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            feedback_type TEXT NOT NULL,
            has_comment INTEGER NOT NULL DEFAULT 0,
            api_key_hash TEXT,
            expected_type TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()


def insert_feedback(
    *,
    conn=None,
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    api_key_hash: Optional[str],
    expected_type: Optional[str] = None,
) -> None:
    """Insert a feedback record. Never stores comment text or secret values.

    Args:
        conn: Optional connection override (for testing).
             If None, uses the Turso connection.
    """
    if conn is None:
        conn = _get_conn()

    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn.execute(
        """INSERT INTO feedback
           (feedback_id, request_id, finding_id, feedback_type, has_comment, api_key_hash, expected_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (feedback_id, request_id, finding_id, feedback_type, int(has_comment), api_key_hash, expected_type, created_at),
    )
    conn.commit()
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd classifinder && python -m pytest tests/test_feedback.py -v`
Expected: All 3 tests PASS

- [ ] **Step 7: Commit**

```bash
cd classifinder
git add app/feedback_store.py tests/test_feedback.py
git commit -m "feat: add feedback_store with Turso table init and insert"
```

---

### Task 2: Add `expected_type` Field to FeedbackRequest

**Files:**
- Modify: `app/models/requests.py:84-110`
- Test: `tests/test_feedback.py`

- [ ] **Step 1: Write failing test for expected_type validation**

Append to `tests/test_feedback.py`:

```python
from app.engine.patterns.registry import PATTERN_REGISTRY


class TestExpectedTypeValidation:
    def test_valid_expected_type_accepted(self):
        """FeedbackRequest accepts a known pattern type as expected_type."""
        from app.models.requests import FeedbackRequest

        # Use the first registered pattern's ID
        valid_type = PATTERN_REGISTRY[0].id

        req = FeedbackRequest(
            request_id="req_test",
            finding_id="f_001",
            feedback_type="false_negative",
            expected_type=valid_type,
        )
        assert req.expected_type == valid_type

    def test_invalid_expected_type_rejected(self):
        """FeedbackRequest rejects an unknown pattern type."""
        from app.models.requests import FeedbackRequest

        with pytest.raises(ValueError, match="expected_type"):
            FeedbackRequest(
                request_id="req_test",
                finding_id="f_001",
                feedback_type="false_negative",
                expected_type="totally_fake_pattern_type",
            )

    def test_none_expected_type_accepted(self):
        """FeedbackRequest accepts None for expected_type (optional field)."""
        from app.models.requests import FeedbackRequest

        req = FeedbackRequest(
            request_id="req_test",
            finding_id="f_001",
            feedback_type="false_positive",
        )
        assert req.expected_type is None

    def test_expected_type_in_json_schema(self):
        """expected_type appears in the JSON schema example."""
        from app.models.requests import FeedbackRequest

        schema = FeedbackRequest.model_json_schema()
        props = schema["properties"]
        assert "expected_type" in props
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestExpectedTypeValidation -v`
Expected: FAIL — `FeedbackRequest` has no `expected_type` field

- [ ] **Step 3: Add expected_type field to FeedbackRequest**

In `app/models/requests.py`, replace the `FeedbackRequest` class (lines 84-110):

```python
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
```

Note: The old `validate_feedback_type` validator is replaced by the new `validate_feedback_fields` which handles both validations. Delete the old validator — do not leave both.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestExpectedTypeValidation -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run existing feedback tests to confirm no regressions**

Run: `cd classifinder && python -m pytest tests/test_api.py -k "Feedback" -v`
Expected: All 5 existing feedback tests PASS

- [ ] **Step 6: Commit**

```bash
cd classifinder
git add app/models/requests.py tests/test_feedback.py
git commit -m "feat: add expected_type field to FeedbackRequest with registry validation"
```

---

### Task 3: Wire Persistence into Feedback Route

**Files:**
- Modify: `app/routes/feedback.py`
- Modify: `app/main.py:28-32`
- Test: `tests/test_feedback.py`

- [ ] **Step 1: Write failing test for Turso persistence via the API**

Append to `tests/test_feedback.py`:

```python
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

api_client = TestClient(app, raise_server_exceptions=True)
TEST_KEY = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
API_HEADERS = {"X-API-Key": TEST_KEY}


class TestFeedbackRoutePersistence:
    def test_feedback_persists_to_turso_when_configured(self):
        """When Turso is available, feedback is inserted into the database."""
        mock_conn = MagicMock()

        with patch("app.routes.feedback.get_settings") as mock_settings, \
             patch("app.routes.feedback._get_feedback_conn", return_value=mock_conn):
            mock_settings.return_value.turso_enabled = True

            r = api_client.post("/v1/feedback", json={
                "request_id": "req_test123",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            }, headers=API_HEADERS)

            assert r.status_code == 202
            # Verify insert was called
            mock_conn.execute.assert_called_once()
            call_args = mock_conn.execute.call_args
            assert "INSERT INTO feedback" in call_args[0][0]

    def test_feedback_falls_back_to_stdout_when_turso_unavailable(self, capsys):
        """When Turso is not configured, feedback is logged to stdout."""
        with patch("app.routes.feedback.get_settings") as mock_settings:
            mock_settings.return_value.turso_enabled = False

            r = api_client.post("/v1/feedback", json={
                "request_id": "req_test456",
                "finding_id": "f_002",
                "feedback_type": "false_negative",
                "expected_type": "aws_access_key",
            }, headers=API_HEADERS)

            assert r.status_code == 202
            captured = capsys.readouterr()
            assert "feedback_received" in captured.out

    def test_feedback_includes_expected_type_in_persistence(self):
        """The expected_type field is passed through to persistence."""
        mock_conn = MagicMock()

        with patch("app.routes.feedback.get_settings") as mock_settings, \
             patch("app.routes.feedback._get_feedback_conn", return_value=mock_conn):
            mock_settings.return_value.turso_enabled = True

            r = api_client.post("/v1/feedback", json={
                "request_id": "req_test789",
                "finding_id": "f_003",
                "feedback_type": "false_negative",
                "expected_type": "aws_access_key",
            }, headers=API_HEADERS)

            assert r.status_code == 202
            call_args = mock_conn.execute.call_args[0]
            params = call_args[1]
            # params tuple: (feedback_id, request_id, finding_id, feedback_type, has_comment, api_key_hash, expected_type, created_at)
            assert params[6] == "aws_access_key"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestFeedbackRoutePersistence -v`
Expected: FAIL — `_get_feedback_conn` doesn't exist yet

- [ ] **Step 3: Rewrite the feedback route with persistence + fallback**

Replace the entire contents of `app/routes/feedback.py`:

```python
"""
ClassiFinder — POST /v1/feedback

Accept false positive / false negative reports. Persists structured metadata
to Turso when configured; falls back to stdout logging when Turso is unavailable.
Never stores comment text or secret values.
"""

import asyncio
import json
import sys
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.models.requests import FeedbackRequest
from app.models.responses import FeedbackResponse

router = APIRouter()

_feedback_conn = None


def _get_feedback_conn():
    """Get or create a Turso connection for feedback persistence."""
    global _feedback_conn
    if _feedback_conn is not None:
        return _feedback_conn
    settings = get_settings()
    if not settings.turso_enabled:
        raise RuntimeError("Turso is not configured")
    import libsql_experimental as libsql
    _feedback_conn = libsql.connect(
        settings.turso_database_url,
        auth_token=settings.turso_auth_token,
    )
    return _feedback_conn


def reset_feedback_conn() -> None:
    """Reset the connection. Used in tests."""
    global _feedback_conn
    _feedback_conn = None


def _persist_to_turso(
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    api_key_hash: str | None,
    expected_type: str | None,
) -> None:
    """Insert feedback row into Turso. Synchronous — call via to_thread."""
    conn = _get_feedback_conn()
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn.execute(
        """INSERT INTO feedback
           (feedback_id, request_id, finding_id, feedback_type, has_comment, api_key_hash, expected_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (feedback_id, request_id, finding_id, feedback_type, int(has_comment), api_key_hash, expected_type, created_at),
    )
    conn.commit()


def _log_to_stdout(
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    expected_type: str | None,
) -> None:
    """Log feedback metadata to stdout (fallback when Turso is unavailable)."""
    log_entry = {
        "event": "feedback_received",
        "feedback_id": feedback_id,
        "request_id": request_id,
        "finding_id": finding_id,
        "feedback_type": feedback_type,
        "has_comment": has_comment,
        "expected_type": expected_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    print(json.dumps(log_entry), file=sys.stdout, flush=True)


@router.post(
    "/v1/feedback",
    response_model=FeedbackResponse,
    status_code=202,
    summary="Report a false positive or false negative",
    description=(
        "Submit feedback on a specific finding from a previous scan. "
        "Only finding metadata is stored — never the original text or secret value. "
        "For false negatives, include expected_type to indicate which pattern you expected. "
        "Returns 202 Accepted immediately."
    ),
)
async def submit_feedback(request: Request, body: FeedbackRequest) -> FeedbackResponse:
    """Validate and persist feedback. Never store or echo the original secret."""
    feedback_id = f"fb_{uuid.uuid4().hex[:6]}"
    settings = get_settings()

    api_key_hash = getattr(request.state, "api_key_hash", None)
    has_comment = body.comment is not None

    if settings.turso_enabled:
        try:
            await asyncio.to_thread(
                _persist_to_turso,
                feedback_id=feedback_id,
                request_id=body.request_id,
                finding_id=body.finding_id,
                feedback_type=body.feedback_type,
                has_comment=has_comment,
                api_key_hash=api_key_hash,
                expected_type=body.expected_type,
            )
        except Exception:
            # Turso write failed — fall back to stdout
            _log_to_stdout(
                feedback_id=feedback_id,
                request_id=body.request_id,
                finding_id=body.finding_id,
                feedback_type=body.feedback_type,
                has_comment=has_comment,
                expected_type=body.expected_type,
            )
    else:
        _log_to_stdout(
            feedback_id=feedback_id,
            request_id=body.request_id,
            finding_id=body.finding_id,
            feedback_type=body.feedback_type,
            has_comment=has_comment,
            expected_type=body.expected_type,
        )

    return FeedbackResponse(feedback_id=feedback_id, status="received")
```

- [ ] **Step 4: Add feedback table init to app lifespan**

In `app/main.py`, modify the lifespan function (lines 28-32). Replace:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize Turso if configured."""
    from app.key_store import init_db
    init_db()
    yield
```

With:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize Turso tables if configured."""
    from app.key_store import init_db
    from app.feedback_store import init_feedback_table
    init_db()
    init_feedback_table()
    yield
```

- [ ] **Step 5: Run new tests to verify they pass**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestFeedbackRoutePersistence -v`
Expected: All 3 tests PASS

- [ ] **Step 6: Run full test suite to confirm no regressions**

Run: `cd classifinder && python -m pytest tests/ -v`
Expected: All tests PASS (57 existing + new feedback tests)

- [ ] **Step 7: Commit**

```bash
cd classifinder
git add app/routes/feedback.py app/main.py tests/test_feedback.py
git commit -m "feat: wire feedback persistence to Turso with stdout fallback"
```

---

### Task 4: Aggregate Query Script

**Files:**
- Create: `scripts/feedback_report.py`
- Test: `tests/test_feedback.py`

- [ ] **Step 1: Write failing test for aggregate queries**

Append to `tests/test_feedback.py`:

```python
class TestFeedbackAggregates:
    def _setup_db(self, tmp_path):
        """Helper: create a local DB with sample feedback data."""
        import libsql_experimental as libsql
        from app.feedback_store import init_feedback_table, insert_feedback

        db_path = str(tmp_path / "test.db")
        conn = libsql.connect(db_path)
        init_feedback_table(conn)

        # Insert sample data
        test_rows = [
            ("fb_01", "req_1", "f_001", "false_positive", False, "hash_a", None),
            ("fb_02", "req_2", "f_002", "false_positive", True, "hash_b", None),
            ("fb_03", "req_3", "f_003", "false_positive", False, "hash_a", None),
            ("fb_04", "req_4", "f_004", "false_negative", False, "hash_c", "aws_access_key"),
            ("fb_05", "req_5", "f_005", "false_negative", True, "hash_d", "aws_access_key"),
            ("fb_06", "req_6", "f_006", "false_negative", False, "hash_a", "openai_api_key"),
        ]
        for row in test_rows:
            insert_feedback(
                conn=conn,
                feedback_id=row[0],
                request_id=row[1],
                finding_id=row[2],
                feedback_type=row[3],
                has_comment=row[4],
                api_key_hash=row[5],
                expected_type=row[6],
            )
        return conn

    def test_false_positive_counts(self, tmp_path):
        """Query returns false positive counts grouped by finding_id."""
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_false_positive_counts

        results = query_false_positive_counts(conn)
        # Should have entries for f_001, f_002, f_003
        assert len(results) == 3

    def test_false_negative_gaps(self, tmp_path):
        """Query returns false negative counts grouped by expected_type."""
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_false_negative_gaps

        results = query_false_negative_gaps(conn)
        # aws_access_key: 2, openai_api_key: 1
        assert len(results) == 2
        # Results should be sorted by count descending
        assert results[0][0] == "aws_access_key"
        assert results[0][1] == 2
        assert results[1][0] == "openai_api_key"
        assert results[1][1] == 1

    def test_volume_by_day(self, tmp_path):
        """Query returns total feedback count grouped by day."""
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_volume_by_day

        results = query_volume_by_day(conn)
        # All 6 entries were inserted on the same day
        assert len(results) == 1
        assert results[0][1] == 6
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestFeedbackAggregates -v`
Expected: FAIL — `cannot import name 'query_false_positive_counts'`

- [ ] **Step 3: Implement aggregate query functions in feedback_store.py**

Append to the end of `app/feedback_store.py`:

```python
# ── Aggregate queries ────────────────────────────────────────────────────────


def query_false_positive_counts(conn=None) -> list[tuple[str, int]]:
    """Return false positive counts grouped by finding_id, descending.

    Returns: [(finding_id, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT finding_id, COUNT(*) as cnt
           FROM feedback
           WHERE feedback_type = 'false_positive'
           GROUP BY finding_id
           ORDER BY cnt DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


def query_false_negative_gaps(conn=None) -> list[tuple[str, int]]:
    """Return false negative counts grouped by expected_type, descending.

    Only includes rows where expected_type is not NULL.
    Returns: [(expected_type, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT expected_type, COUNT(*) as cnt
           FROM feedback
           WHERE feedback_type = 'false_negative' AND expected_type IS NOT NULL
           GROUP BY expected_type
           ORDER BY cnt DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


def query_volume_by_day(conn=None) -> list[tuple[str, int]]:
    """Return total feedback count grouped by day, most recent first.

    Returns: [(date_str, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT SUBSTR(created_at, 1, 10) as day, COUNT(*) as cnt
           FROM feedback
           GROUP BY day
           ORDER BY day DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd classifinder && python -m pytest tests/test_feedback.py::TestFeedbackAggregates -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Create the CLI report script**

Create `scripts/feedback_report.py`:

```python
#!/usr/bin/env python3
"""
ClassiFinder — Feedback Report

CLI tool for querying feedback trends from Turso.

Usage:
    python scripts/feedback_report.py                 # full report
    python scripts/feedback_report.py --fp             # false positives only
    python scripts/feedback_report.py --fn             # false negative gaps only
    python scripts/feedback_report.py --volume         # volume by day only

Requires TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables.
"""

import argparse
import sys
import os

# Add project root to path so app imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_settings
from app.feedback_store import (
    query_false_positive_counts,
    query_false_negative_gaps,
    query_volume_by_day,
)


def print_section(title: str, rows: list[tuple], col1: str, col2: str) -> None:
    """Print a formatted table section."""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")
    if not rows:
        print("  (no data)")
        return
    # Column widths
    max_col1 = max(len(str(r[0])) for r in rows)
    max_col1 = max(max_col1, len(col1))
    print(f"  {col1:<{max_col1}}  {col2}")
    print(f"  {'-' * max_col1}  {'-' * len(col2)}")
    for row in rows:
        print(f"  {str(row[0]):<{max_col1}}  {row[1]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClassiFinder feedback report")
    parser.add_argument("--fp", action="store_true", help="Show false positive counts by finding_id")
    parser.add_argument("--fn", action="store_true", help="Show false negative gaps by expected_type")
    parser.add_argument("--volume", action="store_true", help="Show feedback volume by day")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.turso_enabled:
        print("Error: Turso is not configured. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.", file=sys.stderr)
        sys.exit(1)

    show_all = not (args.fp or args.fn or args.volume)

    if show_all or args.fp:
        rows = query_false_positive_counts()
        print_section("False Positives by Finding ID", rows, "finding_id", "count")

    if show_all or args.fn:
        rows = query_false_negative_gaps()
        print_section("False Negative Gaps by Expected Type", rows, "expected_type", "count")

    if show_all or args.volume:
        rows = query_volume_by_day()
        print_section("Feedback Volume by Day", rows, "date", "count")

    print()


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Commit**

```bash
cd classifinder
git add app/feedback_store.py scripts/feedback_report.py tests/test_feedback.py
git commit -m "feat: add feedback aggregate queries and CLI report script"
```

---

### Task 5: Update API Spec

**Files:**
- Modify: `docs/classifinder-api-spec.md`

- [ ] **Step 1: Update the feedback endpoint documentation**

In `docs/classifinder-api-spec.md`, find the feedback endpoint section (around lines 255-287) and update the request fields table to add `expected_type`. Replace the request fields table with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | yes | The original request ID from a scan/redact response. |
| `finding_id` | string | yes | The specific finding being reported. |
| `feedback_type` | string | yes | `"false_positive"` or `"false_negative"`. |
| `expected_type` | string | no | For false negatives: the pattern type ID you expected (from `GET /v1/types`). Validated against the pattern registry. |
| `comment` | string | no | Optional context. **Not stored** — only a boolean flag indicating its presence is persisted. |

Update the example request JSON to:

```json
{
  "request_id": "req_a1b2c3d4e5f6",
  "finding_id": "f_001",
  "feedback_type": "false_negative",
  "expected_type": "aws_access_key",
  "comment": "This is definitely an AWS key, scanner missed it."
}
```

Update the security note to:

> **Security:** This endpoint stores **only structured metadata** (IDs, type, timestamp, boolean flags) — **never** the comment text, original scanned text, or secret values. The `comment` field is accepted for user convenience but only `has_comment: true/false` is persisted. When Turso is not configured, metadata is logged to stdout only.

- [ ] **Step 2: Commit**

```bash
cd classifinder
git add docs/classifinder-api-spec.md
git commit -m "docs: update API spec with expected_type field on feedback endpoint"
```

---

### Task 6: Final Verification

- [ ] **Step 1: Run the full test suite**

Run: `cd classifinder && python -m pytest tests/ -v`
Expected: All tests PASS — existing 57 tests + new feedback tests

- [ ] **Step 2: Spot-check the dev server**

Run: `cd classifinder && CLASSIFINDER_API_KEYS=ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx uvicorn app.main:app --port 8000 &`

Test the feedback endpoint with expected_type:

```bash
curl -s -X POST http://localhost:8000/v1/feedback \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx" \
  -d '{"request_id":"req_test","finding_id":"f_001","feedback_type":"false_negative","expected_type":"aws_access_key"}' | python -m json.tool
```

Expected: `202 Accepted` with `{"feedback_id": "fb_...", "status": "received"}` — and a JSON log line on stdout with `expected_type`.

Test invalid expected_type:

```bash
curl -s -X POST http://localhost:8000/v1/feedback \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx" \
  -d '{"request_id":"req_test","finding_id":"f_001","feedback_type":"false_negative","expected_type":"nonexistent_type"}' | python -m json.tool
```

Expected: `400` with validation error about `expected_type`.

Kill the dev server after verification.

- [ ] **Step 3: Final commit (if any fixups needed)**

```bash
cd classifinder
git log --oneline -5  # verify commit history looks clean
```
