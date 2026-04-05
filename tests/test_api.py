"""
ClassiFinder — API Integration Tests

Tests all endpoints via FastAPI's TestClient. Uses a test API key injected
via environment variables before the app is imported.

Run with:
    python -m pytest tests/test_api.py -v
"""

import os

# Set test env vars before importing the app
os.environ["CLASSIFINDER_API_KEYS"] = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
os.environ["CLASSIFINDER_RATE_LIMIT_PER_MINUTE"] = "1000"

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=True)

TEST_KEY = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
HEADERS = {"X-API-Key": TEST_KEY}

AWS_TEXT = (
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)

CLEAN_TEXT = "Hello, world! This text contains no secrets."


# ── /v1/health ───────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_no_auth(self):
        """Health endpoint is exempt from auth."""
        r = client.get("/v1/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "patterns_loaded" in data
        assert data["patterns_loaded"] > 0
        assert "uptime_seconds" in data

    def test_health_with_auth(self):
        """Auth header is accepted but not required on health."""
        r = client.get("/v1/health", headers=HEADERS)
        assert r.status_code == 200


# ── /v1/types ────────────────────────────────────────────────────────────────

class TestTypes:
    def test_types_requires_auth(self):
        r = client.get("/v1/types")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "invalid_api_key"

    def test_types_returns_list(self):
        r = client.get("/v1/types", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "types_count" in data
        assert "types" in data
        assert data["types_count"] == len(data["types"])
        assert data["types_count"] > 0

    def test_types_fields(self):
        r = client.get("/v1/types", headers=HEADERS)
        t = r.json()["types"][0]
        for field in ("id", "name", "provider", "severity", "description", "tags"):
            assert field in t, f"Missing field: {field}"

    def test_types_severities_valid(self):
        r = client.get("/v1/types", headers=HEADERS)
        valid = {"critical", "high", "medium", "low"}
        for t in r.json()["types"]:
            assert t["severity"] in valid


# ── /v1/scan ─────────────────────────────────────────────────────────────────

class TestScan:
    def test_scan_requires_auth(self):
        r = client.post("/v1/scan", json={"text": AWS_TEXT})
        assert r.status_code == 401

    def test_scan_invalid_key(self):
        r = client.post("/v1/scan", json={"text": AWS_TEXT}, headers={"X-API-Key": "bad_key"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "invalid_api_key"

    def test_scan_finds_aws_keys(self):
        # AKIAIOSFODNN7EXAMPLE is a known test value (confidence=0.15); use min_confidence=0.1
        r = client.post(
            "/v1/scan",
            json={"text": AWS_TEXT, "min_confidence": 0.1},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["findings_count"] >= 1
        assert len(data["findings"]) == data["findings_count"]
        types_found = {f["type"] for f in data["findings"]}
        assert "aws_access_key" in types_found

    def test_scan_clean_text(self):
        r = client.post("/v1/scan", json={"text": CLEAN_TEXT}, headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["findings_count"] == 0
        assert data["findings"] == []

    def test_scan_response_fields(self):
        r = client.post("/v1/scan", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        data = r.json()
        assert "request_id" in data
        assert data["request_id"].startswith("req_")
        assert "scan_time_ms" in data
        assert "summary" in data
        for key in ("critical", "high", "medium", "low"):
            assert key in data["summary"]

    def test_scan_finding_fields(self):
        r = client.post("/v1/scan", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        f = r.json()["findings"][0]
        for field in (
            "id", "type", "type_name", "provider", "severity", "confidence",
            "value_preview", "span", "is_likely_test_value", "recommendation", "matched_pattern"
        ):
            assert field in f, f"Missing field: {field}"
        assert "start" in f["span"] and "end" in f["span"]

    def test_scan_value_preview_masked(self):
        """Full secret must never appear in value_preview."""
        r = client.post("/v1/scan", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        for f in r.json()["findings"]:
            assert "AKIAIOSFODNN7EXAMPLE" not in f["value_preview"]

    def test_scan_context_included_by_default(self):
        r = client.post("/v1/scan", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        for f in r.json()["findings"]:
            assert f["context"] is not None

    def test_scan_context_excluded(self):
        r = client.post(
            "/v1/scan",
            json={"text": AWS_TEXT, "include_context": False, "min_confidence": 0.1},
            headers=HEADERS,
        )
        for f in r.json()["findings"]:
            assert f["context"] is None

    def test_scan_type_filter(self):
        r = client.post(
            "/v1/scan",
            json={"text": AWS_TEXT, "types": ["aws_access_key"], "min_confidence": 0.1},
            headers=HEADERS,
        )
        data = r.json()
        for f in data["findings"]:
            assert f["type"] == "aws_access_key"

    def test_scan_min_confidence_filter(self):
        r = client.post(
            "/v1/scan",
            json={"text": AWS_TEXT, "min_confidence": 0.99},
            headers=HEADERS,
        )
        for f in r.json()["findings"]:
            assert f["confidence"] >= 0.99

    def test_scan_missing_text_field(self):
        r = client.post("/v1/scan", json={}, headers=HEADERS)
        assert r.status_code == 422 or r.status_code == 400

    def test_scan_rate_limit_headers(self):
        r = client.post("/v1/scan", json={"text": CLEAN_TEXT}, headers=HEADERS)
        assert "x-ratelimit-limit" in r.headers
        assert "x-ratelimit-remaining" in r.headers
        assert "x-ratelimit-reset" in r.headers


# ── /v1/redact ───────────────────────────────────────────────────────────────

class TestRedact:
    def test_redact_requires_auth(self):
        r = client.post("/v1/redact", json={"text": AWS_TEXT})
        assert r.status_code == 401

    def test_redact_clean_text(self):
        r = client.post("/v1/redact", json={"text": CLEAN_TEXT}, headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["findings_count"] == 0
        assert data["redacted_text"] == CLEAN_TEXT

    def test_redact_label_style(self):
        r = client.post(
            "/v1/redact",
            json={"text": AWS_TEXT, "redaction_style": "label", "min_confidence": 0.1},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert "AKIAIOSFODNN7EXAMPLE" not in data["redacted_text"]
        assert "_REDACTED]" in data["redacted_text"]

    def test_redact_mask_style(self):
        r = client.post(
            "/v1/redact",
            json={"text": AWS_TEXT, "redaction_style": "mask", "min_confidence": 0.1},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" not in r.json()["redacted_text"]

    def test_redact_hash_style(self):
        r = client.post(
            "/v1/redact",
            json={"text": AWS_TEXT, "redaction_style": "hash", "min_confidence": 0.1},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "REDACTED:sha256:" in r.json()["redacted_text"]

    def test_redact_invalid_style(self):
        r = client.post(
            "/v1/redact",
            json={"text": AWS_TEXT, "redaction_style": "base64"},
            headers=HEADERS,
        )
        assert r.status_code in (400, 422)

    def test_redact_finding_fields(self):
        r = client.post("/v1/redact", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        data = r.json()
        assert data["findings_count"] >= 1
        f = data["findings"][0]
        for field in ("id", "type", "severity", "confidence", "span", "redacted_as"):
            assert field in f, f"Missing field: {field}"

    def test_redact_response_fields(self):
        r = client.post("/v1/redact", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        data = r.json()
        for field in ("request_id", "scan_time_ms", "findings_count", "redacted_text", "summary"):
            assert field in data

    def test_redact_no_context_in_findings(self):
        """Redact findings should not expose context (no context field)."""
        r = client.post("/v1/redact", json={"text": AWS_TEXT, "min_confidence": 0.1}, headers=HEADERS)
        for f in r.json()["findings"]:
            assert "context" not in f


# ── /v1/feedback ─────────────────────────────────────────────────────────────

class TestFeedback:
    def test_feedback_requires_auth(self):
        r = client.post(
            "/v1/feedback",
            json={
                "request_id": "req_abc",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
            },
        )
        assert r.status_code == 401

    def test_feedback_accepted(self):
        r = client.post(
            "/v1/feedback",
            json={
                "request_id": "req_abc123",
                "finding_id": "f_001",
                "feedback_type": "false_positive",
                "comment": "This is a UUID.",
            },
            headers=HEADERS,
        )
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "received"
        assert data["feedback_id"].startswith("fb_")

    def test_feedback_false_negative(self):
        r = client.post(
            "/v1/feedback",
            json={
                "request_id": "req_xyz",
                "finding_id": "f_002",
                "feedback_type": "false_negative",
            },
            headers=HEADERS,
        )
        assert r.status_code == 202

    def test_feedback_invalid_type(self):
        r = client.post(
            "/v1/feedback",
            json={
                "request_id": "req_abc",
                "finding_id": "f_001",
                "feedback_type": "wrong_type",
            },
            headers=HEADERS,
        )
        assert r.status_code in (400, 422)

    def test_feedback_missing_required_field(self):
        r = client.post(
            "/v1/feedback",
            json={"request_id": "req_abc"},
            headers=HEADERS,
        )
        assert r.status_code in (400, 422)


# ── Auth edge cases ───────────────────────────────────────────────────────────

class TestAuth:
    def test_missing_key_header(self):
        r = client.post("/v1/scan", json={"text": CLEAN_TEXT})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "invalid_api_key"

    def test_empty_key_header(self):
        r = client.post("/v1/scan", json={"text": CLEAN_TEXT}, headers={"X-API-Key": ""})
        assert r.status_code == 401

    def test_error_response_shape(self):
        r = client.post("/v1/scan", json={"text": CLEAN_TEXT})
        body = r.json()
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]
