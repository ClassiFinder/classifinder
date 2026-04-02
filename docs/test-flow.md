# End-to-End Test Flow

Test the complete user journey. Run each step in order. If any step fails, stop and fix before continuing.

---

## Step 1: Health Check

```bash
curl https://api.classifinder.tech/v1/health
```

**Expected:** `{"status": "healthy", "version": "1.0.0", "patterns_loaded": 71, ...}`

---

## Step 2: Create an API Key

```bash
curl -X POST https://api.classifinder.tech/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email": "testflow@example.com"}'
```

**Expected:** 201 with `{"api_key": "ss_live_...", "email": "testflow@example.com", ...}`

Save the key — you'll use it in every step below. Replace `YOUR_KEY` with it.

---

## Step 3: Duplicate Email Rejected

```bash
curl -X POST https://api.classifinder.tech/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email": "testflow@example.com"}'
```

**Expected:** 409 with `{"error": {"code": "email_already_registered", ...}}`

---

## Step 4: Auth Works

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "hello world"}'
```

**Expected:** 200 with `{"findings_count": 0, ...}`

---

## Step 5: Auth Rejects Bad Key

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_live_fake_key_that_does_not_exist_1234567890" \
  -d '{"text": "hello world"}'
```

**Expected:** 401 with `{"error": {"code": "invalid_api_key", ...}}`

---

## Step 6: Scan — Cloud Keys

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
```

**Expected:** Finds `aws_access_key` (critical, high confidence). The secret key may also be found as a test value with low confidence.

---

## Step 7: Scan — AI Provider Keys

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234\nANTHROPIC_API_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901"}'
```

**Expected:** Finds `openai_api_key` and `anthropic_api_key`, both critical.

---

## Step 8: Scan — Payment Keys

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "STRIPE_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd\nCARD=4532015112830366"}'
```

**Expected:** Finds `stripe_live_secret_key` (critical) and `credit_card_number` (high, Luhn-valid).

---

## Step 9: Scan — VCS & Comms

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\nSLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx\nSENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs"}'
```

**Expected:** Finds `github_pat_classic`, `slack_bot_token`, `sendgrid_api_key`.

---

## Step 10: Scan — Database

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "DATABASE_URL=postgres://admin:s3cur3p4ss@db.internal:5432/production\nMONGO_URL=mongodb+srv://user:MyP4ssword@cluster0.abc123.mongodb.net/mydb"}'
```

**Expected:** Finds `postgres_connection_string` and `mongodb_connection_string`.

---

## Step 11: Redact — The Key Feature

```bash
curl -X POST https://api.classifinder.tech/v1/redact \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "Deploy with key AKIAJGKJHSKLDJFH3284 and stripe sk_live_51H3aKLkdsjfhDKJSH38djfhksd to prod server postgres://admin:p4ss@db:5432/app"}'
```

**Expected:** `redacted_text` has all three secrets replaced:
- `[AWS_ACCESS_KEY_REDACTED]`
- `[STRIPE_LIVE_SECRET_KEY_REDACTED]`
- `[POSTGRES_CONNECTION_STRING_REDACTED]`

---

## Step 12: Redact — Mask Style

```bash
curl -X POST https://api.classifinder.tech/v1/redact \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "key=sk_live_51H3aKLkdsjfhDKJSH38djfhksd", "redaction_style": "mask"}'
```

**Expected:** `redacted_text` shows `sk_l****************************` (first 4 chars preserved, rest masked).

---

## Step 13: Redact — Hash Style

```bash
curl -X POST https://api.classifinder.tech/v1/redact \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text": "key=sk_live_51H3aKLkdsjfhDKJSH38djfhksd", "redaction_style": "hash"}'
```

**Expected:** `redacted_text` shows `[REDACTED:sha256:a1b2c3d4]` (deterministic hash for deduplication).

---

## Step 14: Types Endpoint

```bash
curl https://api.classifinder.tech/v1/types \
  -H "X-API-Key: YOUR_KEY"
```

**Expected:** 200 with `types_count: 71` and a list of all pattern metadata.

---

## Step 15: Feedback Endpoint

```bash
curl -X POST https://api.classifinder.tech/v1/feedback \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"request_id": "req_test123", "finding_id": "f_001", "feedback_type": "false_positive", "comment": "This is a UUID, not an API key."}'
```

**Expected:** 202 with `{"feedback_id": "fb_...", "status": "received"}`

---

## Step 16: Key Rotation

```bash
curl -X POST https://api.classifinder.tech/v1/keys/rotate \
  -H "X-API-Key: YOUR_KEY"
```

**Expected:** 200 with a new `api_key`. The old key should stop working. Test by repeating Step 4 with the old key (should get 401) and the new key (should get 200).

---

## Step 17: Clean Text — No False Positives

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_NEW_KEY" \
  -d '{"text": "Hello, this is a normal email about the project meeting next Tuesday. Please review the quarterly report and let me know your thoughts. The budget for Q3 is $1.2 million, and we need to allocate resources. Contact me at thomas@example.com or call 555-0123. The tracking number is 1Z999AA10123456784 and the order ID is ORD-2026-03-24-001."}'
```

**Expected:** `findings_count: 0`. No false positives on normal business text.

---

## Step 18: Realistic .env File (Kitchen Sink)

```bash
curl -X POST https://api.classifinder.tech/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_NEW_KEY" \
  -d '{"text": "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDATABASE_URL=postgres://admin:p4ssw0rd@db.internal:5432/prod\nSTRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd\nGITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\nSENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs\nSLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx\nOPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234\nANTHROPIC_API_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901"}'
```

**Expected:** 7+ findings across cloud, payment, VCS, comms, AI, and database categories. The summary should show a mix of critical and high severity.

---

## Results Checklist

```
[ ] Step 1:  Health — 200, 71 patterns
[ ] Step 2:  Key create — 201, got key
[ ] Step 3:  Duplicate — 409
[ ] Step 4:  Auth works — 200
[ ] Step 5:  Bad auth — 401
[ ] Step 6:  Cloud keys — found aws_access_key
[ ] Step 7:  AI keys — found openai + anthropic
[ ] Step 8:  Payment — found stripe + credit card
[ ] Step 9:  VCS/Comms — found github + slack + sendgrid
[ ] Step 10: Database — found postgres + mongodb
[ ] Step 11: Redact label — secrets replaced with labels
[ ] Step 12: Redact mask — first 4 chars preserved
[ ] Step 13: Redact hash — sha256 hash tokens
[ ] Step 14: Types — 71 types listed
[ ] Step 15: Feedback — 202 received
[ ] Step 16: Rotate — new key works, old key rejected
[ ] Step 17: Clean text — 0 findings
[ ] Step 18: Kitchen sink — 7+ findings, mixed severity
```
