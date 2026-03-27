# Key Provisioning — Design Spec

**Date:** 2026-03-23
**Status:** Approved (rev 2 — post-review fixes)

---

## Overview

Self-serve API key provisioning via a new `POST /v1/keys/create` endpoint. Users submit their email, receive an API key immediately. Keys are hashed (SHA-256) and stored in Turso (hosted SQLite). The auth middleware checks an in-memory cache first, then Turso, then falls back to the existing `CLASSIFINDER_API_KEYS` env var. If Turso is unavailable, auth degrades gracefully to env-var-only mode.

---

## Decisions

| Decision | Choice |
|----------|--------|
| Key storage | Turso (hosted SQLite) |
| Key creation auth | Open with rate limits (no email verification) |
| Rate limits | 1 key per email, 5 keys per IP per hour (persisted in DB) |
| Key delivery | JSON response only (no email) |
| Existing keys | Env var fallback preserved |
| Turso client | `libsql-experimental` via `asyncio.to_thread()` |
| Auth caching | In-memory LRU cache of valid key hashes, 60s TTL |
| Turso failure mode | Fall back to env-var-only (never block requests due to DB outage) |
| CORS | `/v1/keys/create` restricted to `classifinder.tech` origin |

---

## Flow

1. User fills out form on classifinder.tech with their email
2. Landing page POSTs to `POST /v1/keys/create` with `{"email": "user@example.com"}`
3. API normalizes email (lowercase, strip whitespace), validates format, checks rate limits via SQL
4. API generates a 48-char key: `ss_live_` + 40 random hex chars
5. API hashes the key with SHA-256 (full 64-char hex digest), stores hash + email + metadata in Turso
6. API returns `{"api_key": "ss_live_...", "email": "...", "created_at": "..."}`
7. Landing page displays the key with a copy button and "save this — you won't see it again" warning
8. On subsequent API requests, auth middleware checks in-memory cache → Turso → env var fallback

---

## New Endpoint: POST /v1/keys/create

**Auth:** None required (this is how users get their first key).

**CORS:** Restricted to `classifinder.tech` origin only (not the global `*` policy).

**Exempt from:** API key auth, standard rate limiting.

**Has its own rate limits** (enforced via SQL queries, survive restarts):
- 1 key per email address (duplicate email returns 409 Conflict)
- 5 key creation requests per IP per hour: `SELECT COUNT(*) FROM api_keys WHERE created_by_ip = ? AND created_at > ?`

**Email normalization:** Emails are lowercased and stripped of whitespace before validation and storage.

**Request:**

```json
{
  "email": "user@example.com"
}
```

**Response (201 Created):**

```json
{
  "api_key": "ss_live_a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
  "email": "user@example.com",
  "created_at": "2026-03-23T15:30:00Z",
  "message": "Save this key — you will not see it again."
}
```

**Error responses** (follow existing envelope format):

```json
{"error": {"code": "invalid_email", "message": "...", "retry_after": null}}
```

| Status | Code | When |
|--------|------|------|
| 400 | `invalid_email` | Email is missing or malformed |
| 409 | `email_already_registered` | A key already exists for this email |
| 429 | `key_creation_rate_limit` | Too many key creation requests from this IP |

---

## New Endpoint: POST /v1/keys/rotate

**Auth:** Required — authenticated by the current (old) key via `X-API-Key` header.

Revokes the old key and issues a new one for the same email.

**Request:** Empty body (the key to revoke is in the header).

**Response (200 OK):**

```json
{
  "api_key": "ss_live_<new_key>",
  "email": "user@example.com",
  "created_at": "2026-03-23T16:00:00Z",
  "message": "Previous key has been revoked. Save this new key — you will not see it again."
}
```

Under the hood: sets `revoked_at` on the old key row, inserts a new row with the new key hash and the same email. The in-memory cache is invalidated for the old hash.

---

## Auth Middleware Change

Current: Check `X-API-Key` against `CLASSIFINDER_API_KEYS` env var (comma-separated list).

New — three-step lookup:
1. Hash the incoming key with SHA-256 (full 64-char digest via `_hash_key_full()`)
2. Check in-memory LRU cache (capacity 1024, TTL 60s). If hit → authenticated.
3. If cache miss, query Turso: `SELECT key_hash FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`
   - Run via `asyncio.to_thread()` to avoid blocking the event loop
   - On success → add to cache, authenticated
   - On Turso exception (timeout, connection error) → log warning, fall through to step 4
4. Fall back to `CLASSIFINDER_API_KEYS` env var list
5. If not found in any → return 401

The existing `_hash_key()` (truncated, 8 chars) remains for logging. A new `_hash_key_full()` (full SHA-256) is used for storage and lookup.

**Turso graceful degradation:** If the Turso query raises any exception, the middleware logs a warning and falls back to env-var-only mode. API requests from admin keys always work. Turso-provisioned keys temporarily fail during outages but the API never returns 500 due to a DB issue.

---

## Turso Schema

```sql
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    email TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    created_by_ip TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_active
    ON api_keys(email) WHERE revoked_at IS NULL;
```

- `key_hash`: Full SHA-256 hex digest of the API key (64 chars)
- `key_prefix`: First 12 chars of the key (e.g. `ss_live_a3f8`) for identification in logs/admin
- `email`: User's email, unique among active (non-revoked) keys
- `tier`: For future use (`free`, `starter`, `pro`)
- `created_by_ip`: IP address from `X-Forwarded-For` header (for rate limit enforcement via SQL)
- `created_at`: ISO 8601 timestamp
- `revoked_at`: ISO 8601 timestamp, NULL if active

**Database initialization:** `app/key_store.py` includes an `init_db()` function that runs `CREATE TABLE IF NOT EXISTS` during the FastAPI lifespan startup. No separate migration tool needed.

---

## IP Address Resolution

The API runs behind Fly.io's proxy. Client IP is read from the `X-Forwarded-For` header (first value). If the header is absent, falls back to `request.client.host`. This is used only for rate limit enforcement on `/v1/keys/create` — never logged alongside request content.

---

## Turso Optional Mode

If `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` env vars are absent:
- Key provisioning endpoints (`/v1/keys/create`, `/v1/keys/rotate`) return 503 with `{"error": {"code": "key_provisioning_unavailable", "message": "Key provisioning is not configured."}}`
- Auth middleware skips the Turso lookup step, uses env-var-only mode
- All existing functionality works as before

This preserves the local development experience — you can run the API without Turso.

---

## Files

| File | Action | Purpose |
|------|--------|---------|
| `app/key_store.py` | Create | Turso client, `init_db()`, key generation, hash storage, hash lookup, in-memory cache |
| `app/routes/keys.py` | Create | `POST /v1/keys/create` and `POST /v1/keys/rotate` endpoints |
| `app/models/requests.py` | Modify | Add `KeyCreateRequest` model |
| `app/models/responses.py` | Modify | Add `KeyCreateResponse` model |
| `app/middleware/auth.py` | Modify | Three-step lookup: cache → Turso → env var |
| `app/main.py` | Modify | Register keys router, exempt from auth, CORS restriction, lifespan `init_db()` |
| `app/config.py` | Modify | Add `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` (optional) |
| `requirements.txt` | Modify | Add `libsql-experimental` |
| `tests/test_keys.py` | Create | Key creation, duplicate email, rate limit, rotation, auth lookup, Turso-down fallback tests |

---

## Configuration

Two new environment variables (optional — system works without them):

| Variable | Example | Where Set |
|----------|---------|-----------|
| `TURSO_DATABASE_URL` | `libsql://classifinder-yourname.turso.io` | `fly secrets` |
| `TURSO_AUTH_TOKEN` | `eyJ...` | `fly secrets` |

---

## Dependency

One new package: `libsql-experimental` (Turso's Python SDK).

Added to `requirements.txt`.

---

## What Does NOT Change

- The engine (`app/engine/`) — untouched
- Existing endpoints (`/v1/scan`, `/v1/redact`, `/v1/types`, `/v1/health`, `/v1/feedback`) — untouched
- The `/v1/health` endpoint — still exempt from auth
- Existing admin keys in `CLASSIFINDER_API_KEYS` — still work via env var fallback
