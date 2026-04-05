# Security Audit — 2026-04-05

First CSO audit across the full ClassiFinder monorepo. Daily mode (8/10 confidence gate), all 14 phases.

## Scope

All 8 repos: classifinder, classifinder-engine, classifinder-sdk, classifinder-site, classifinder-mcp, cfsniff, classifinder-tests, classifinder-benchmark.

## Results

**0 CRITICAL | 1 HIGH | 6 MEDIUM | 2 LOW** (14 candidates scanned, 5 filtered as DoS/rate-limiting/intentional design)

## Findings and Fixes

| # | Sev | Finding | Fix | Commit |
|---|-----|---------|-----|--------|
| 1 | HIGH | `superfly/flyctl-actions/setup-flyctl@master` — any upstream push executes in our pipeline with `FLY_API_TOKEN` | SHA-pinned to `@63da3ecc...` | classifinder `8f09138` |
| 2 | MED | API key comparison not timing-safe (`if api_key in settings.api_keys`) | `hmac.compare_digest()` in `auth.py:64` | classifinder `8f09138` |
| 3 | MED | 6 repos missing `.env` in `.gitignore` | Added `.env`, `.env.*`, `.gstack/` to all 6 | All repos |
| 4 | MED | No Python lockfiles — all deps use `>=` pins, builds non-reproducible | `uv lock` for all 5 Python repos + `requirements.lock` for Dockerfile | All Python repos |
| 5 | MED | All GitHub Actions tag-pinned (v4/v5/v3), not SHA-pinned | SHA-pinned all 7 action refs across 3 workflows | classifinder, classifinder-site, cfsniff |
| 6 | MED | All 3 Dockerfiles run as root | Added `appuser` non-root user | classifinder, classifinder-engine |
| 7 | MED | No CODEOWNERS on workflow files | Deferred — low priority while solo | — |
| 8 | LOW | Self-XSS in Demo.astro `innerHTML` with unsanitized user text | HTML entity escaping before innerHTML | classifinder-site `4b6de32` |
| 9 | LOW | classifinder-engine/ has no `.dockerignore` | Created from classifinder/ template | classifinder-engine `a5d6052` |

## Bonus Fixes

- cfsniff `requires-python` bumped `3.9` to `3.10` (classifinder SDK requires 3.10+)
- classifinder `pyproject.toml` now includes `httpx` and `libsql-experimental` (were only in requirements.txt)
- Dockerfile and CI now install from `requirements.lock` instead of `requirements.txt`

## What Was Clean

- No secrets in git history (all 8 repos scanned)
- No SQL injection (all Turso queries use parameterized statements)
- No ReDoS (all 101 regex patterns use bounded quantifiers)
- No SSRF (scanner is pure regex, no I/O)
- No prompt injection (MCP server passes text to scan/redact only, no dynamic prompts)
- Logging follows "never log bodies" rule (metadata only)
- Secrets management correct (all via env vars / Fly.io secrets / GitHub Secrets)
- API key storage sound (SHA-256 hashes in Turso)

## Filtered Out

These were flagged by scan agents but excluded per the confidence gate:

- **Unbounded in-memory rate limit dicts** — DoS/resource exhaustion, auto-excluded
- **X-Forwarded-For spoofable for rate limit bypass** — rate limiting issue, auto-excluded
- **CORS wildcard origins** — intentional design for API-first product, no credentials

## Tool

Audit performed with gstack `/cso` skill (v0.15.8.0), 4 parallel agents covering phases 1-9. Report saved to `.gstack/security-reports/2026-04-05-140000.json`.

## Next Audit

Run `/cso` again after any of: new endpoints added, new dependencies, new collaborators with write access, or monthly cadence.
