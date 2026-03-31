# ClassiFinder — API Specification

Version: 1.0.0-draft
Base URL: `https://api.classifinder.ai/v1`

---

## Authentication

All requests require an API key passed in the `X-API-Key` header.

```
X-API-Key: ss_live_abc123def456...
```

Key format: `ss_live_` prefix (production) or `ss_test_` prefix (sandbox, no billing). Keys are 48 characters total.

---

## Rate Limits

Rate limits are returned in response headers on every request:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 997
X-RateLimit-Reset: 1711152000
```

| Tier       | Requests/minute | Max payload size |
|------------|----------------|------------------|
| Free       | 60             | 256 KB           |
| Starter    | 300            | 512 KB           |
| Pro        | 1,000          | 1 MB             |
| Enterprise | Custom         | 5 MB             |

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.

---

## Endpoints

### POST /v1/scan

Scan text for secrets and credentials. Returns structured findings without modifying the input.

**Request:**

```json
{
  "text": "string (required) — the text to scan, max 1MB",
  "types": ["string (optional) — filter to specific secret types, e.g. [\"aws_access_key\", \"stripe_key\"]. Default: all"],
  "min_confidence": 0.5,
  "include_context": true
}
```

| Field            | Type     | Required | Default | Description |
|------------------|----------|----------|---------|-------------|
| `text`           | string   | yes      | —       | Text to scan. Max size per tier. |
| `types`          | string[] | no       | `["all"]` | Secret types to detect. Use `GET /v1/types` for the full list. |
| `min_confidence` | float    | no       | `0.5`   | Minimum confidence threshold (0.0–1.0). Findings below this are excluded. |
| `include_context`| boolean  | no       | `true`  | If true, include a short text snippet around each finding for human review. |

**Response (200 OK):**

```json
{
  "request_id": "req_a1b2c3d4e5f6",
  "scan_time_ms": 7,
  "findings_count": 3,
  "findings": [
    {
      "id": "f_001",
      "type": "aws_access_key",
      "type_name": "AWS Access Key ID",
      "provider": "aws",
      "severity": "critical",
      "confidence": 0.98,
      "value_preview": "AKIA****MPLE",
      "span": {
        "start": 22,
        "end": 42
      },
      "context": "...AWS_ACCESS_KEY_ID=AKIA************MPLE\nAWS_SECRET...",
      "is_likely_test_value": false,
      "recommendation": "Rotate this key immediately in the AWS IAM console and audit its usage in CloudTrail.",
      "matched_pattern": "aws_access_key_v1"
    },
    {
      "id": "f_002",
      "type": "aws_secret_key",
      "type_name": "AWS Secret Access Key",
      "provider": "aws",
      "severity": "critical",
      "confidence": 0.96,
      "value_preview": "wJal****EKEY",
      "span": {
        "start": 58,
        "end": 98
      },
      "context": "...AWS_SECRET_ACCESS_KEY=wJal************EKEY\nDATABASE...",
      "is_likely_test_value": false,
      "recommendation": "Rotate this secret key immediately. It is paired with the access key found in this scan.",
      "matched_pattern": "aws_secret_key_v1"
    },
    {
      "id": "f_003",
      "type": "database_connection_string",
      "type_name": "Database Connection String (with password)",
      "provider": "postgresql",
      "severity": "high",
      "confidence": 0.94,
      "value_preview": "postgres://admin:****@db.internal:5432/prod",
      "span": {
        "start": 113,
        "end": 160
      },
      "context": "...DATABASE_URL=postgres://admin:****@db.internal:5432/prod\n...",
      "is_likely_test_value": false,
      "recommendation": "Rotate the database password and use a secrets manager to inject credentials at runtime.",
      "matched_pattern": "postgres_connection_string_v1"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

**Finding Fields:**

| Field               | Type    | Description |
|---------------------|---------|-------------|
| `id`                | string  | Unique finding ID within this response. |
| `type`              | string  | Machine-readable secret type identifier. |
| `type_name`         | string  | Human-readable secret type name. |
| `provider`          | string  | Service provider (aws, stripe, github, etc.) or "generic". |
| `severity`          | string  | `critical` / `high` / `medium` / `low`. |
| `confidence`        | float   | Detection confidence from 0.0 to 1.0. |
| `value_preview`     | string  | Partially masked value showing prefix/suffix only. Never the full secret. |
| `span`              | object  | Character offsets (start inclusive, end exclusive) in the original text. |
| `context`           | string  | Optional. Short snippet around the finding with the secret masked. |
| `is_likely_test_value` | boolean | True if the value matches known test/example credentials. |
| `recommendation`    | string  | Actionable remediation guidance. |
| `matched_pattern`   | string  | Internal pattern ID that triggered (useful for reporting false positives). |

---

### POST /v1/redact

Scan text and return a sanitized version with all detected secrets replaced by type labels. Also returns the findings list so the caller knows what was redacted.

**Request:**

```json
{
  "text": "string (required)",
  "types": ["string (optional)"],
  "min_confidence": 0.5,
  "redaction_style": "label"
}
```

| Field              | Type   | Required | Default   | Description |
|--------------------|--------|----------|-----------|-------------|
| `text`             | string | yes      | —         | Text to redact. |
| `types`            | string[] | no     | `["all"]` | Secret types to detect and redact. |
| `min_confidence`   | float  | no       | `0.5`     | Minimum confidence to trigger redaction. |
| `redaction_style`  | string | no       | `"label"` | How to replace secrets: `"label"` → `[AWS_KEY_REDACTED]`, `"mask"` → `AKIA**************`, `"hash"` → `[REDACTED:sha256:a1b2c3]` (for deduplication). |

**Response (200 OK):**

```json
{
  "request_id": "req_x9y8z7w6v5u4",
  "scan_time_ms": 8,
  "findings_count": 3,
  "redacted_text": "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]\nAWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_REDACTED]\nDATABASE_URL=[DATABASE_CONNECTION_STRING_REDACTED]",
  "findings": [
    {
      "id": "f_001",
      "type": "aws_access_key",
      "severity": "critical",
      "confidence": 0.98,
      "span": { "start": 22, "end": 42 },
      "redacted_as": "[AWS_ACCESS_KEY_REDACTED]"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

The `redacted_text` field is the primary output for agents using this as LLM preprocessing middleware. The text is safe to forward to a model.

---

### GET /v1/types

List all supported secret types with metadata.

**Response (200 OK):**

```json
{
  "types_count": 50,
  "types": [
    {
      "id": "aws_access_key",
      "name": "AWS Access Key ID",
      "provider": "aws",
      "severity": "critical",
      "description": "AWS IAM access key, typically 20 characters starting with AKIA.",
      "tags": ["cloud", "aws", "iam"]
    },
    {
      "id": "stripe_live_key",
      "name": "Stripe Live Secret Key",
      "provider": "stripe",
      "severity": "critical",
      "description": "Stripe live-mode secret API key, starting with sk_live_.",
      "tags": ["payment", "stripe"]
    }
  ]
}
```

This endpoint is essential for agent self-discovery. An agent can call this to learn what the API detects, build UI around it, or filter scan requests to relevant types.

---

### GET /v1/health

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "patterns_loaded": 50,
  "uptime_seconds": 86400
}
```

---

### POST /v1/feedback

Report false positives or false negatives to improve detection quality over time.

**Request:**

```json
{
  "request_id": "req_a1b2c3d4e5f6",
  "finding_id": "f_001",
  "feedback_type": "false_positive",
  "comment": "This is a UUID, not an API key."
}
```

| Field           | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `request_id`    | string | yes      | The original request ID. |
| `finding_id`    | string | yes      | The specific finding being reported. |
| `feedback_type` | string | yes      | `"false_positive"` or `"false_negative"`. |
| `comment`       | string | no       | Optional context. |

**Response (202 Accepted):**

```json
{
  "feedback_id": "fb_123456",
  "status": "received"
}
```

Note: This endpoint stores only the finding metadata (type, pattern, confidence) and the feedback classification — never the original text or secret value.

---

## Error Responses

All errors follow the same structure:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "You have exceeded your rate limit of 60 requests per minute.",
    "retry_after": 32
  }
}
```

| Status | Code                    | When |
|--------|-------------------------|------|
| 400    | `invalid_request`       | Missing required fields, malformed JSON. |
| 400    | `payload_too_large`     | Text exceeds tier size limit. |
| 401    | `invalid_api_key`       | Missing, malformed, or revoked API key. |
| 403    | `tier_limit_exceeded`   | Feature not available on current tier. |
| 429    | `rate_limit_exceeded`   | Too many requests. Includes `Retry-After`. |
| 500    | `internal_error`        | Something went wrong. Contact support. |

---

## Pricing Tiers (Draft)

| Tier       | Monthly Price | Requests/month | Payload Limit | Features |
|------------|--------------|----------------|---------------|----------|
| Free       | $0           | 10,000         | 256 KB        | /scan, /redact, /types. Community support. |
| Starter    | $19          | 200,000        | 512 KB        | Everything in Free. Email support. |
| Pro        | $49          | 1,000,000      | 1 MB          | Everything in Starter. Priority support. Batch endpoint. |
| Enterprise | Custom       | Unlimited      | 5 MB          | Everything in Pro. Custom patterns. SLA. Dedicated support. Self-hosted option. |

Overage pricing (Starter and above): $0.001 per additional request.

**Positioning vs competitors:**
- GitGuardian free tier: 10,000 calls/month (same as ours, but their API is a secondary feature)
- Nightfall free tier: 3 GB/month (harder to compare, but roughly similar for typical payloads)
- GitHub Advanced Security: $19/active committer/month (completely different model, repo-only)
- Our edge: Usage-based pricing that scales with agent/pipeline volume, not human headcount

---

## SDK and Integration Targets (Post-MVP)

### Python SDK
```python
from classifinder import ClassiFinder

client = ClassiFinder(api_key="ss_live_...")
result = client.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
print(result.findings[0].type)  # "aws_access_key"

safe_text = client.redact(user_input).redacted_text
llm_response = openai.chat(messages=[{"role": "user", "content": safe_text}])
```

### LangChain Integration
```python
from classifinder.integrations.langchain import ClassiFinderGuard

chain = prompt | ClassiFinderGuard(api_key="ss_live_...") | llm | output_parser
```

### GitHub Action (Coming Soon)
```yaml
# Not yet published — planned integration
- uses: classifinder/scan-action@v1
  with:
    api-key: ${{ secrets.CLASSIFINDER_API_KEY }}
    path: "."
    fail-on: "critical,high"
```

### Express/Node Middleware
```javascript
const { classiFinderMiddleware } = require("classifinder");

app.use("/api/chat", classiFinderMiddleware({
  apiKey: process.env.CLASSIFINDER_API_KEY,
  redact: true,
  field: "body.message"
}));
```

---

## OpenAPI 3.1 Spec Location

The full machine-readable OpenAPI spec will be served at:
- `https://api.classifinder.tech/v1/openapi.json`
- `https://api.classifinder.tech/docs` (Swagger UI)

This is critical for agent function-calling. Agents using OpenAI/Anthropic function calling can import the spec directly to auto-generate tool definitions.
