# Hard Questions — And How to Answer Them

Questions a skeptical senior engineer or security-minded developer would ask about ClassiFinder, and honest answers. Use these for: landing page copy, Show HN replies, Twitter threads, blog posts, FAQ page, and sales conversations.

---

## 1. "You say nothing is stored. How do I verify that?"

**Answer:** The code that processes your text is open source at [github.com/ThomasParas/classifinder-engine](https://github.com/ThomasParas/classifinder-engine). You can read every line — there are no database calls, no file writes, no network calls to a logging service. It's a pure function: text in, findings out, text discarded.

The Dockerfile is also published. The production container runs Python, FastAPI, and Uvicorn — nothing else. No database driver, no persistent volume, no logging SDK that captures request bodies.

We also publish the exact schema of what we log: request ID, API key hash (first 8 chars of SHA-256), timestamp, HTTP method, endpoint path, payload size in bytes, finding count (a number, not the findings), response time, and status code. That's it. Never request bodies, never response bodies, never secret values.

**What we can't prove:** That the deployed server matches the open-source code exactly. That's a trust problem every hosted API has — it's the same reason you trust OpenAI's privacy policy. Long-term, a SOC 2 Type II audit is the answer. For now, the open-source engine is the strongest trust signal we can offer.

---

## 2. "You added Turso for key storage. Your architecture doc says 'no database.' Which is it?"

**Answer:** The scanner engine is stateless — it has no database and stores nothing. Turso stores only API key hashes and email addresses for authentication. It never sees, stores, or has access to the text you scan.

The distinction: Turso is in the auth layer, not the data path. Your text goes from your request → into memory → through the scanner → back in the response → garbage collected. Turso is only consulted to answer "is this API key valid?" before the scanner ever runs.

**Honest framing:** "The scanning engine is stateless. The auth layer uses a database for key management. Your text never touches it."

---

## 3. "50 patterns is thin. GitGuardian has 550+. What do you miss?"

**Answer:** We'll miss some. If your user pastes a Datadog API key, a Vercel token, or a custom internal token format, we won't catch it today. We cover the 50 most common and highest-risk secret types — the ones that appear most frequently in LLM pipelines and .env files.

GitGuardian has been building their library for years with a large team. We're growing ours based on what our users actually encounter. You can report missing patterns via the `/v1/feedback` endpoint or GitHub issues, and we'll add them.

**Honest framing:** "We catch the 50 most dangerous patterns. We're growing, and we're transparent about what we don't cover yet. No scanner catches everything — not even GitGuardian."

---

## 4. "What's your false positive rate?"

**Answer:** We don't have production-scale data yet to publish a number. What we can tell you about the architecture:

- Prefix-anchored patterns (AWS `AKIA`, Stripe `sk_live_`, GitHub `ghp_`) have near-zero false positives because the prefix is unique to that service.
- Context-dependent patterns (generic API keys, high-entropy strings) are where false positives happen. We use Shannon entropy analysis, context keyword boosting, and known-test-value filtering to reduce them.
- Credit card detection uses Luhn checksum validation — any number that fails the checksum is dropped.
- The confidence score (0.0–1.0) lets you set your own threshold. At the default 0.5, most false positives are already filtered. Set it to 0.8 for higher precision.

**Honest framing:** "We optimize for low false positives through entropy analysis, context signals, and Luhn validation. We'll publish precision/recall data once we have enough production volume. In the meantime, the confidence score lets you control the trade-off."

---

## 5. "That <5ms number — is that real end-to-end latency?"

**Answer:** No. <5ms is the P50 engine time — the time the scanner takes to process text in memory. It doesn't include network latency, TLS handshake, auth middleware, or Turso lookup.

Real end-to-end latency depends on where you're calling from. From a server in the US, expect 50-150ms total (dominated by network round-trip to our SJC region). The scanner itself adds single-digit milliseconds on top of the network baseline.

**Honest framing:** "<5ms engine time. Total latency depends on your network distance — comparable to any API call to a US-West server." We should benchmark and publish real P50/P99 numbers.

---

## 6. "Your compliance section implies you're SOC 2 certified. Are you?"

**Answer:** No. We are not SOC 2 certified, and we should not imply that we are.

ClassiFinder helps you satisfy specific SOC 2 and PCI-DSS controls by providing auditable secret scanning evidence. The structured JSON findings, metadata-only logs, and redaction capabilities support your compliance program — but we are not ourselves certified.

**Revised landing page copy:**
- "Supports your SOC 2 program" not "Satisfies SOC 2"
- "Helps meet PCI-DSS Requirement 8.6.3" not "Proves compliance"
- Include: "ClassiFinder is not itself SOC 2 or PCI-DSS certified. We provide tooling that supports your compliance program."

**This is the most important copy fix before launch.** Overstating compliance claims can damage trust with exactly the audience that cares most about compliance.

---

## 7. "Your auth is just an API key in a header. What about key theft?"

**Answer:** You're right — if someone intercepts your API key, they can use your quota. This is the same auth model as OpenAI, Anthropic, Stripe, and most API services.

Mitigations in place:
- HTTPS only — keys are encrypted in transit
- Keys are never stored — we store only SHA-256 hashes
- Key rotation is available via `POST /v1/keys/rotate`
- Rate limiting (60 req/min) bounds the damage of a stolen key

What we don't have yet: OAuth, IP allowlisting, or key scoping (restrict a key to specific endpoints). These are on the roadmap for paid tiers.

**Honest framing:** "API key auth over HTTPS — the same model as every major API. Key rotation available. OAuth and IP restrictions planned for paid tiers."

---

## 8. "Redacted text still contains context around the secret. Isn't that a leak?"

**Answer:** Good catch. If the original text is `"the password for admin is hunter2 on server db.prod.internal"`, the redacted output is `"the password for admin is [DATABASE_PASSWORD_REDACTED] on server db.prod.internal"`. The username and server name are preserved because they're not secrets by our pattern definitions.

This is by design — redaction replaces the *credential*, not the surrounding context. The surrounding text is needed for the LLM to understand the message. If we stripped everything around every secret, the redacted text would be unintelligible.

For users who need aggressive redaction, the `mask` style replaces the secret with asterisks (preserving only 4 prefix chars), and the `hash` style replaces it with a deterministic hash token. Neither leaks the secret value.

**Honest framing:** "We redact the credential, not the context. If your text contains sensitive metadata beyond the secret itself (server names, usernames), consider whether the surrounding text is also sensitive for your use case. ClassiFinder detects credentials, not PII."

---

## 9. "What happens if ClassiFinder is down? Does my LangChain chain fail?"

**Answer:** With the current implementation, yes — if the API is unreachable and retries are exhausted, the guard raises an `APIConnectionError` and the chain fails.

This should be improved. The guard should have a `fail_open=True` option (default) that passes text through unmodified when the API is unreachable, so the pipeline never breaks because of us. Security-critical pipelines can set `fail_open=False` to hard-fail.

**TODO:** Implement `fail_open` parameter on `ClassiFinderGuard`. Until then, users can wrap the chain in a try/except.

**Honest framing (once implemented):** "If ClassiFinder is unreachable, the guard passes text through unmodified by default. Your pipeline never breaks because of us. Set `fail_open=False` if you'd rather block than risk an unscanned prompt."

---

## 10. "You're a solo dev. What happens if you disappear?"

**Answer:** The scanner engine is open source (MIT licensed). If ClassiFinder the company stops existing, the code doesn't. Anyone can fork it, host it, and maintain it.

The SDK is on PyPI. The API spec is published. The patterns are in a public GitHub repo. There's no vendor lock-in — the worst case is you self-host the engine (it's a single Python file with no dependencies beyond `re`).

**Honest framing:** "The engine is open source. The patterns are public. If we disappear, you fork and self-host. No lock-in."

---

## 11. "60 requests per minute for free is 86,400 per day. Why would anyone pay?"

**Answer:** Because most production workloads need burst capacity, not sustained throughput. 60 req/min is 1 request per second — fine for development and light usage. A production pipeline processing user input in real-time will hit that ceiling fast.

Paid tiers will offer higher rate limits (300/min for Starter, 1000/min for Pro), larger payloads (512KB/1MB), and priority support. The free tier is generous enough to build and test on, but constraining enough that production workloads outgrow it.

**Honest framing:** "Free is generous for building and testing. Production workloads with concurrent users will need higher limits. Paid tiers coming soon."

---

## 12. "Regex can't catch everything. What about secrets without a known format?"

**Answer:** You're absolutely right. Regex-based scanning catches secrets with structural patterns — prefixes like `sk_live_`, `AKIA`, `ghp_`, or formats like connection strings and PEM blocks. It cannot catch:

- Custom internal token formats your company invented
- Passwords in natural language ("the password is swordfish")
- Secrets with no structural pattern (a random 32-char string with no context)
- Rotated keys with a new prefix that hasn't been added to our library yet

This is a fundamental limitation of pattern matching, and every regex-based scanner (GitGuardian, TruffleHog, GitLeaks) shares it. ML-based detection (like Nightfall) can catch some of these, but at the cost of higher latency, higher false positive rates, and opaque confidence scoring.

ClassiFinder is honest about this: we catch known formats with high precision. We're one layer of defense, not the only layer.

**Honest framing:** "We catch 50 known secret formats with high precision and low false positives. We don't catch custom formats, natural language passwords, or structureless secrets. No regex scanner does. Use us as one layer of a defense-in-depth strategy."

---

## Summary: Questions We Answer Well

| # | Question | Strength of our answer |
|---|----------|----------------------|
| 1 | How do I verify no storage? | Strong — open-source engine + Dockerfile |
| 2 | Database contradiction? | Strong — clear separation of auth vs data path |
| 3 | Only 50 patterns? | Honest — growing, transparent about gaps |
| 7 | API key auth security? | Adequate — standard model, rotation available |
| 8 | Context leakage in redaction? | Strong — by design, multiple styles available |
| 10 | Solo dev bus factor? | Strong — open source, no lock-in |
| 12 | Regex limitations? | Strong — honest about what we can't do |

## Questions That Need Work

| # | Question | What to do |
|---|----------|-----------|
| 4 | False positive rate? | Publish data once we have volume |
| 5 | Real latency? | Benchmark and publish actual P50/P99 |
| 6 | Compliance claims? | Soften landing page copy before launch |
| 9 | LangChain failure mode? | Implement `fail_open` parameter |
| 11 | Why pay? | Will resolve itself when paid tiers launch |
