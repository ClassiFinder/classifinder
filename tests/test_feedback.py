import os
os.environ.setdefault("CLASSIFINDER_API_KEYS", "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx")
os.environ.setdefault("CLASSIFINDER_RATE_LIMIT_PER_MINUTE", "1000")

import libsql_experimental as libsql
import pytest

from app.feedback_store import init_feedback_table, insert_feedback


def _make_conn(tmp_path):
    """Create a local SQLite connection for testing."""
    return libsql.connect(str(tmp_path / "test.db"))


class TestFeedbackStoreInit:
    def test_init_creates_feedback_table(self, tmp_path):
        """init_feedback_table creates the table; a manual insert succeeds."""
        conn = _make_conn(tmp_path)
        init_feedback_table(conn=conn)

        # Manual insert should not raise
        conn.execute(
            """
            INSERT INTO feedback
                (feedback_id, request_id, finding_id, feedback_type,
                 has_comment, expected_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "fb_test_001",
                "req_abc",
                "fnd_xyz",
                "false_positive",
                0,
                None,
                "2026-03-26T00:00:00Z",
            ),
        )
        conn.commit()

        row = conn.execute(
            "SELECT feedback_id FROM feedback WHERE feedback_id = ?",
            ("fb_test_001",),
        ).fetchone()
        assert row is not None
        assert row[0] == "fb_test_001"


class TestInsertFeedback:
    def test_insert_feedback_stores_row(self, tmp_path):
        """insert_feedback persists all fields correctly, including expected_type."""
        conn = _make_conn(tmp_path)
        init_feedback_table(conn=conn)

        insert_feedback(
            conn=conn,
            feedback_id="fb_test_002",
            request_id="req_001",
            finding_id="fnd_001",
            feedback_type="false_positive",
            has_comment=True,
            expected_type="aws_access_key",
        )

        row = conn.execute(
            """
            SELECT feedback_id, request_id, finding_id, feedback_type,
                   has_comment, expected_type, created_at
            FROM feedback
            WHERE feedback_id = ?
            """,
            ("fb_test_002",),
        ).fetchone()

        assert row is not None
        feedback_id, request_id, finding_id, feedback_type, has_comment, expected_type, created_at = row

        assert feedback_id == "fb_test_002"
        assert request_id == "req_001"
        assert finding_id == "fnd_001"
        assert feedback_type == "false_positive"
        assert has_comment == 1  # stored as integer
        assert expected_type == "aws_access_key"
        assert created_at is not None
        assert "T" in created_at  # ISO 8601 format

    def test_insert_feedback_without_expected_type(self, tmp_path):
        """insert_feedback stores NULL for expected_type when not provided."""
        conn = _make_conn(tmp_path)
        init_feedback_table(conn=conn)

        insert_feedback(
            conn=conn,
            feedback_id="fb_test_003",
            request_id="req_002",
            finding_id="fnd_002",
            feedback_type="false_negative",
            has_comment=False,
            expected_type=None,
        )

        row = conn.execute(
            "SELECT expected_type, has_comment FROM feedback WHERE feedback_id = ?",
            ("fb_test_003",),
        ).fetchone()

        assert row is not None
        expected_type, has_comment = row
        assert expected_type is None
        assert has_comment == 0


class TestExpectedTypeValidation:
    def test_valid_expected_type_accepted(self):
        import app.engine.scanner  # noqa: F401 — triggers pattern registration
        from app.engine.patterns.registry import PATTERN_REGISTRY
        from app.models.requests import FeedbackRequest
        valid_type = PATTERN_REGISTRY[0].id
        req = FeedbackRequest(
            request_id="req_test", finding_id="f_001",
            feedback_type="false_negative", expected_type=valid_type,
        )
        assert req.expected_type == valid_type

    def test_invalid_expected_type_rejected(self):
        from app.models.requests import FeedbackRequest
        with pytest.raises(ValueError, match="expected_type"):
            FeedbackRequest(
                request_id="req_test", finding_id="f_001",
                feedback_type="false_negative", expected_type="totally_fake_pattern_type",
            )

    def test_none_expected_type_accepted(self):
        from app.models.requests import FeedbackRequest
        req = FeedbackRequest(
            request_id="req_test", finding_id="f_001", feedback_type="false_positive",
        )
        assert req.expected_type is None

    def test_expected_type_in_json_schema(self):
        from app.models.requests import FeedbackRequest
        schema = FeedbackRequest.model_json_schema()
        assert "expected_type" in schema["properties"]


from unittest.mock import patch, MagicMock  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

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
            # params: (feedback_id, request_id, finding_id, feedback_type, has_comment, expected_type, created_at)
            assert params[5] == "aws_access_key"


class TestFeedbackAggregates:
    def _setup_db(self, tmp_path):
        """Helper: create a local DB with sample feedback data."""
        import libsql_experimental as libsql
        from app.feedback_store import init_feedback_table, insert_feedback

        db_path = str(tmp_path / "test.db")
        conn = libsql.connect(db_path)
        init_feedback_table(conn)

        test_rows = [
            ("fb_01", "req_1", "f_001", "false_positive", False, None),
            ("fb_02", "req_2", "f_002", "false_positive", True, None),
            ("fb_03", "req_3", "f_003", "false_positive", False, None),
            ("fb_04", "req_4", "f_004", "false_negative", False, "aws_access_key"),
            ("fb_05", "req_5", "f_005", "false_negative", True, "aws_access_key"),
            ("fb_06", "req_6", "f_006", "false_negative", False, "openai_api_key"),
        ]
        for row in test_rows:
            insert_feedback(
                conn=conn,
                feedback_id=row[0], request_id=row[1], finding_id=row[2],
                feedback_type=row[3], has_comment=row[4],
                expected_type=row[5],
            )
        return conn

    def test_false_positive_counts(self, tmp_path):
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_false_positive_counts
        results = query_false_positive_counts(conn)
        assert len(results) == 3

    def test_false_negative_gaps(self, tmp_path):
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_false_negative_gaps
        results = query_false_negative_gaps(conn)
        assert len(results) == 2
        assert results[0][0] == "aws_access_key"
        assert results[0][1] == 2
        assert results[1][0] == "openai_api_key"
        assert results[1][1] == 1

    def test_volume_by_day(self, tmp_path):
        conn = self._setup_db(tmp_path)
        from app.feedback_store import query_volume_by_day
        results = query_volume_by_day(conn)
        assert len(results) == 1
        assert results[0][1] == 6


class TestFeedbackRateLimit:
    def setup_method(self):
        from app.routes.feedback import reset_feedback_rate_limit
        reset_feedback_rate_limit()

    def test_under_limit_succeeds(self):
        """Requests under the limit return 202."""
        with patch("app.routes.feedback.get_settings") as mock_settings:
            mock_settings.return_value.turso_enabled = False
            r = api_client.post("/v1/feedback", json={
                "request_id": "req_rl_1",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            }, headers=API_HEADERS)
            assert r.status_code == 202

    def test_over_limit_returns_429(self):
        """After 10 requests in an hour, the 11th returns 429."""
        from app.routes.feedback import reset_feedback_rate_limit
        reset_feedback_rate_limit()

        with patch("app.routes.feedback.get_settings") as mock_settings:
            mock_settings.return_value.turso_enabled = False

            for i in range(10):
                r = api_client.post("/v1/feedback", json={
                    "request_id": f"req_rl_{i}",
                    "finding_id": "f_001",
                    "feedback_type": "false_positive",
                }, headers=API_HEADERS)
                assert r.status_code == 202, f"Request {i} should succeed"

            # 11th request should be rate limited
            r = api_client.post("/v1/feedback", json={
                "request_id": "req_rl_overflow",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            }, headers=API_HEADERS)
            assert r.status_code == 429
            data = r.json()
            assert data["error"]["code"] == "feedback_rate_limit_exceeded"
            assert "retry_after" in data["error"]

    def test_window_expiration_drops_old_timestamps(self):
        """Old timestamps drop out of the 1h window; a request after expiration succeeds."""
        from app.routes.feedback import (
            reset_feedback_rate_limit,
            _feedback_log,
            FEEDBACK_WINDOW_SECONDS,
        )
        reset_feedback_rate_limit()

        with patch("app.routes.feedback.get_settings") as mock_settings, \
             patch("time.monotonic") as mock_time:
            mock_settings.return_value.turso_enabled = False

            mock_time.return_value = 1000.0
            for i in range(10):
                r = api_client.post("/v1/feedback", json={
                    "request_id": f"req_exp_{i}",
                    "finding_id": "f_001",
                    "feedback_type": "false_positive",
                }, headers=API_HEADERS)
                assert r.status_code == 202

            # Within window: limit hit
            r = api_client.post("/v1/feedback", json={
                "request_id": "req_within_window",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            }, headers=API_HEADERS)
            assert r.status_code == 429

            # Past window: old timestamps drop, request succeeds
            mock_time.return_value = 1000.0 + FEEDBACK_WINDOW_SECONDS + 1
            r = api_client.post("/v1/feedback", json={
                "request_id": "req_after_expire",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            }, headers=API_HEADERS)
            assert r.status_code == 202

            key_hash = next(iter(_feedback_log))
            assert len(_feedback_log[key_hash]) == 1
