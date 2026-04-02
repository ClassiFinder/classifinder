# ClassiFinder — Technical Architecture

*Working name. Other candidates: ScanVault, RedactAPI, SecretSieve, LeakShield*

---

## Product Summary

ClassiFinder is a lightweight, stateless API that scans arbitrary text for leaked secrets and credentials. It returns structured JSON with detection type, confidence, severity, span locations, and optionally a redacted version of the input. The primary audience is developers building AI agents, LLM-powered applications, and CI/CD pipelines who need a fast, zero-ops way to detect and strip credentials from text before it enters a model context, gets logged, or is passed downstream.

---

## Core Design Principles

1. **Stateless and ephemeral.** The API processes text in memory and returns results. Nothing is stored. No request bodies are logged. This is a privacy-first architecture — users are sending us their secrets by definition.

2. **Agent-first contract.** Every response is structured JSON designed for programmatic consumption. Confidence scores, severity levels, span locations, and pattern identifiers let agents make decisions without human review.

3. **Sub-50ms latency target.** Regex-based scanning of typical payloads (under 100KB) should complete in single-digit milliseconds. The 50ms ceiling accounts for network overhead and is competitive with any alternative.

4. **Minimal surface area.** Two core endpoints. No dashboards, no incident management, no Git integrations. Those are GitGuardian's territory. We are a scanning primitive.

---

## System Architecture

```
Client (agent, CI pipeline, middleware)
  │
  ├── POST /v1/scan     → Detect secrets, return findings
  ├── POST /v1/redact    → Detect secrets, return sanitized text
  └── GET  /v1/health    → Service health check
  │
  ▼
┌─────────────────────────────────────────────────┐
│  API Gateway / Edge Layer                        │
│  - API key validation                            │
│  - Rate limiting (per key, per tier)             │
│  - Request size validation (max 1MB)             │
│  - CORS headers                                  │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│  Scanner Engine (core, no I/O, pure functions)   │
│                                                  │
│  1. Text Preprocessor                            │
│     - Normalize line endings                     │
│     - Decode base64 blocks inline                │
│     - Expand escaped sequences                   │
│                                                  │
│  2. Pattern Matcher                              │
│     - Run all active patterns against text       │
│     - Named capture groups extract key fields    │
│     - Return raw match set with spans            │
│                                                  │
│  3. Entropy Analyzer                             │
│     - Shannon entropy on generic matches         │
│     - Filter low-entropy false positives         │
│                                                  │
│  4. Confidence Scorer                            │
│     - Pattern specificity (prefix match = high)  │
│     - Entropy score for generic patterns         │
│     - Context signals (nearby "key", "token",    │
│       "password", "secret" keywords)             │
│     - Known test/example key filtering           │
│                                                  │
│  5. Deduplicator & Overlap Resolver              │
│     - Overlapping spans: keep highest confidence │
│     - Identical values: merge into one finding   │
│                                                  │
│  6. Redactor (if /v1/redact)                     │
│     - Replace matched spans with type labels     │
│     - Preserve surrounding text and line numbers  │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Why This is Simple

The scanner engine is a pure function: `text in → findings out`. No database, no queue, no background workers, no state. This means:
- Horizontal scaling is trivial (every instance is identical)
- Testing is deterministic (same input always produces same output)
- Deployment is simple (single container or serverless function)
- Security posture is strong (nothing to breach because nothing is stored)

---

## Pattern Library Architecture

The pattern library is the core intellectual property. It's a structured registry of detection rules organized by secret type.

### Pattern Definition Schema

Each pattern is defined as:

```python
@dataclass
class SecretPattern:
    id: str                    # e.g., "aws_access_key"
    name: str                  # e.g., "AWS Access Key ID"
    description: str           # Human-readable explanation
    severity: str              # "critical" | "high" | "medium" | "low"
    regex: re.Pattern          # Compiled regex with named groups
    confidence_base: float     # Base confidence before context adjustment (0.0-1.0)
    entropy_threshold: float   # Minimum Shannon entropy (0.0 = skip check)
    known_test_values: set     # Known example/test values to exclude
    context_keywords: list     # Nearby words that boost confidence
    recommendation: str        # What to do if found
    provider: str              # e.g., "aws", "stripe", "github"
    tags: list                 # e.g., ["cloud", "payment", "vcs"]
```

### Pattern Categories (71 Types)

**Cloud Provider Keys (15 patterns)**
- AWS Access Key ID (AKIA prefix, 20 chars)
- AWS Secret Access Key (40 chars, paired with access key)
- GCP Service Account Key (JSON fragment with private_key field)
- GCP API Key (AIza prefix, 39 chars)
- Azure Storage Account Key (base64, 88 chars)
- Azure AD Client Secret
- DigitalOcean Personal Access Token (dop_v1_ prefix)
- Heroku API Key (specific format)
- Cloudflare API Token (specific format)
- IBM Cloud IAM Key
- Oracle Cloud API Key
- Alibaba Cloud AccessKey
- Linode API Token
- Vultr API Key
- Hetzner API Token

**Payment & Financial (5 patterns)**
- Stripe Live/Test Secret Key (sk_live_ / sk_test_ prefix)
- Stripe Publishable Key (pk_live_ / pk_test_ prefix)
- Stripe Webhook Signing Secret (whsec_ prefix)
- PayPal Client Secret
- Square Access Token

**Version Control & CI/CD (8 patterns)**
- GitHub Personal Access Token (ghp_ prefix, classic)
- GitHub Fine-Grained Token (github_pat_ prefix)
- GitHub OAuth App Secret
- GitLab Personal Access Token (glpat- prefix)
- GitLab Pipeline Trigger Token
- Bitbucket App Password
- CircleCI API Token
- Jenkins API Token

**Communication & SaaS (8 patterns)**
- Slack Bot Token (xoxb- prefix)
- Slack User Token (xoxp- prefix)
- Slack Webhook URL
- Twilio Account SID + Auth Token
- SendGrid API Key (SG. prefix)
- Mailgun API Key (key- prefix)
- Discord Bot Token
- Telegram Bot Token

**Database & Infrastructure (7 patterns)**
- PostgreSQL Connection String (postgres:// with password)
- MySQL Connection String
- MongoDB Connection String (mongodb+srv:// with password)
- Redis Connection String (redis:// with password)
- Database password in .env format (DB_PASSWORD=, DATABASE_PASSWORD=)
- SSH Private Key (-----BEGIN ... PRIVATE KEY-----)
- Generic PEM/PKCS8 Private Key blocks

**Auth Tokens & Generic (7 patterns)**
- JWT Token (eyJ prefix, 3 dot-separated base64 segments)
- Bearer Token in Authorization header format
- Basic Auth credentials (base64-encoded user:pass)
- OAuth Client Secret (generic format, context-dependent)
- Generic API Key in .env format (API_KEY=, SECRET_KEY=, etc.)
- Generic high-entropy string (32+ chars, high Shannon entropy, near context keywords)
- Password in URL (https://user:password@host)

### Known Test Values (False Positive Reduction)

Maintain a set of well-known example/test/placeholder values that should not trigger alerts:

- AWS example keys from documentation (AKIAIOSFODNN7EXAMPLE, wJalrXUtnFEMI/K7MDENG...)
- Stripe test keys (sk_test_... from Stripe docs)
- Common placeholder strings ("your-api-key-here", "xxxxxxxxxxxx", "REPLACE_ME", etc.)
- GitHub's example tokens from documentation
- Common test UUIDs and hash values

This list grows over time from false positive reports.

---

## Confidence Scoring Algorithm

Confidence is calculated per finding, not globally. The algorithm:

```
confidence = base_confidence
           + context_boost      (0.0 to +0.10)
           - low_entropy_penalty (0.0 to -0.30)
           - test_value_penalty  (0.0 to -0.80)

Clamped to [0.05, 0.99]
```

**base_confidence** comes from the pattern definition:
- Prefix-anchored patterns (AKIA, sk_live_, ghp_) → 0.95
- Structural patterns (connection strings, PEM blocks) → 0.90
- Format-only patterns (high-entropy strings) → 0.60

**context_boost**: +0.02 per context keyword found within 50 chars of the match (e.g., "key", "token", "secret", "password", "credential", "auth"). Max +0.10.

**low_entropy_penalty**: For generic patterns only (base < 0.80), if Shannon entropy of the matched value is below the pattern's threshold, reduce confidence. This catches things like "AAAAAAAAAAAAAAAA" matching a generic key pattern.

**test_value_penalty**: If the matched value is in the known_test_values set, reduce confidence to 0.15 and set a `is_likely_test_value: true` flag.

---

## Technology Choices

### Option A: Python (FastAPI) — Recommended for MVP

**Pros:** Fastest development time. `re` module handles all needed patterns. FastAPI generates OpenAPI docs automatically. Pydantic models give you request/response validation for free. Easiest to iterate on patterns (edit a Python file, redeploy). Most accessible for contributors.

**Cons:** Slower per-request than Rust/Go (but still sub-10ms for typical payloads, so this doesn't matter at MVP scale).

**Stack:**
- FastAPI + Uvicorn
- Python `re` module (stdlib) + `regex` package (for Unicode/possessive quantifiers if needed)
- Pydantic v2 for models
- API key auth via middleware (keys stored in env vars or Cloudflare KV at scale)
- Rate limiting via in-memory sliding window or Redis at scale

### Option B: Rust (Actix) — For Scale

Only consider this if latency becomes a real bottleneck at high volume (millions of requests/day). Regex crate is extremely fast but development velocity is much slower.

### Option C: Go — Middle Ground

If Betterleaks gains traction and you want to potentially share pattern definitions with it, Go alignment could matter. But this is speculative.

**Recommendation:** Start with Python/FastAPI. Port the scanner engine to Rust only if benchmarks at scale justify it (they probably won't for years).

### Deployment

**Phase 1 (MVP):** Cloudflare Workers (if Python support is mature enough) or Railway/Fly.io ($2-5/month).

**Phase 2 (Growth):** AWS Lambda behind API Gateway. Auto-scales, pay-per-request, handles bursty CI pipeline traffic well.

**Phase 3 (Scale):** Multi-region deployment with edge routing. Only needed at millions of daily requests.

---

## Security Architecture

### Data Handling — The Cardinal Rules

1. **Never log request bodies.** Not in application logs, not in access logs, not in error reports. Users are sending us secrets. Logging them defeats the purpose of the product.

2. **Never persist request data.** No database of scanned text. No request replay. No analytics on content. Process in memory, return results, discard.

3. **Log only metadata.** Request ID, API key hash (not the key itself), timestamp, response time, finding count (not finding content), HTTP status. This is enough for debugging and billing.

4. **TLS everywhere.** HTTPS only. No HTTP fallback.

5. **API keys, not user accounts.** No passwords to breach. Keys are revocable and rotatable. Store only salted hashes of keys.

### What We Can Log (for billing and ops)

```json
{
  "request_id": "uuid",
  "api_key_hash": "sha256_prefix",
  "timestamp": "2026-03-22T...",
  "endpoint": "/v1/scan",
  "input_size_bytes": 4096,
  "finding_count": 3,
  "response_time_ms": 7,
  "status_code": 200
}
```

This is enough to bill, monitor, debug latency, and detect abuse without ever seeing the content.

---

## File Structure (Python/FastAPI)

```
classifinder/
├── app/
│   ├── main.py                 # FastAPI app, middleware, CORS
│   ├── routes/
│   │   ├── scan.py             # POST /v1/scan
│   │   ├── redact.py           # POST /v1/redact
│   │   └── health.py           # GET /v1/health
│   ├── engine/
│   │   ├── scanner.py          # Core scan function (pure, no I/O)
│   │   ├── patterns/
│   │   │   ├── registry.py     # Pattern loader and registry
│   │   │   ├── cloud.py        # AWS, GCP, Azure, etc.
│   │   │   ├── payment.py      # Stripe, PayPal, Square
│   │   │   ├── vcs.py          # GitHub, GitLab, Bitbucket
│   │   │   ├── comms.py        # Slack, Twilio, SendGrid
│   │   │   ├── database.py     # Connection strings, passwords
│   │   │   └── generic.py      # High-entropy, JWT, PEM, .env
│   │   ├── entropy.py          # Shannon entropy calculator
│   │   ├── confidence.py       # Confidence scoring logic
│   │   ├── redactor.py         # Text redaction logic
│   │   └── test_values.py      # Known test/example values
│   ├── models/
│   │   ├── request.py          # Pydantic request models
│   │   └── response.py         # Pydantic response models
│   ├── auth/
│   │   └── api_key.py          # API key validation middleware
│   └── config.py               # Settings, rate limits, feature flags
├── tests/
│   ├── corpus/
│   │   ├── true_positives/     # Text files containing known secrets
│   │   └── false_positives/    # Text that looks like secrets but isn't
│   ├── test_scanner.py         # Core engine tests
│   ├── test_patterns.py        # Per-pattern accuracy tests
│   ├── test_confidence.py      # Scoring tests
│   └── test_api.py             # Integration tests
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## Testing Strategy

### Pattern Accuracy Tests

For each pattern, maintain at least:
- 10 true positive examples (real format, varied)
- 10 true negative examples (similar-looking strings that should NOT match)
- 3 edge cases (truncated, surrounded by unusual characters, embedded in JSON/YAML)

Target: 99%+ true positive rate, <2% false positive rate across the corpus.

### Performance Benchmarks

- Scan 1KB of text: target < 5ms
- Scan 10KB of text: target < 15ms
- Scan 100KB of text: target < 50ms
- Scan 1MB of text (max size): target < 200ms

Run on every PR. Alert if any benchmark regresses by > 20%.

### Integration Tests

- Full request/response cycle for both endpoints
- API key validation (valid, invalid, expired, rate-limited)
- Oversized request handling (> 1MB rejection)
- Unicode handling (secrets in UTF-8 documents)
- Empty input, null fields, malformed JSON

---

## Scaling Considerations (Future)

Things we don't need now but should design to allow later:

- **Batch endpoint** (`POST /v1/scan/batch`): Accept an array of text blocks, return findings per block. Useful for CI pipelines scanning multiple files.
- **Webhook notifications**: For long-running batch jobs, POST results to a callback URL.
- **Custom pattern upload**: Let enterprise customers define their own patterns (internal secret formats). This is a strong enterprise upsell.
- **SDK wrappers**: Python package (`pip install classifinder`), npm package, Go module. These are thin HTTP client wrappers but dramatically lower adoption friction.
- **Framework integrations**: LangChain tool, LlamaIndex callback, Vercel AI SDK middleware. These are the distribution play that Gemini correctly identified as critical.
