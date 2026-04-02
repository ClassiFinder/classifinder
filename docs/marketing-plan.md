# ClassiFinder — Launch Marketing Plan

## The Narrative

"Every secret scanner was built for Git. This one's built for AI."

ClassiFinder is the first secret scanner designed for LLM pipelines, not Git repos. One API call strips credentials from text before it reaches your model. Open-source engine, Python SDK, LangChain integration, MCP server. Free.

---

## Launch Channels (in order)

### Day 1: Show HN

**Why:** Hacker News is where developer tools live or die. A strong Show HN gets you 5,000-20,000 visitors, GitHub stars, and early adopters who will actually use the product and give feedback.

**What they care about:** Technical depth, honesty, solo builder narrative, open source, no bullshit.

**Draft post:**

> **Show HN: ClassiFinder — Secret scanning API built for AI pipelines, not Git repos**
>
> I built ClassiFinder because I watched an AI agent paste an AWS key into GPT and realized no scanner was built for that use case.
>
> GitGuardian scans repos. TruffleHog crawls commit histories. But in 2026, secrets leak when users paste .env files into ChatGPT, when RAG pipelines surface credentials, and when agents hardcode keys into generated code.
>
> ClassiFinder is a stateless API: POST your text, GET it back clean. 88 secret types, sub-5ms engine time, nothing stored. The engine is open source — the code that touches your data is auditable.
>
> What's different:
> - Never returns the full secret (masked preview only — the scanner doesn't become a leak)
> - Native redaction on the free tier (not just detection)
> - Numeric confidence scores (0.0-1.0, not "VERY_LIKELY")
> - Python SDK: `pip install classifinder`
> - LangChain integration: `chain = prompt | ClassiFinderGuard() | llm`
> - MCP server: `pip install classifinder-mcp` (works with Claude Code, Cursor)
> - Credit card detection with Luhn validation
>
> Free tier: 60 req/min, 256KB payloads, all 82 detectors. No credit card.
>
> Live API: https://classifinder.tech
> Open-source engine: https://github.com/ThomasParas/classifinder-engine
> SDK: https://pypi.org/project/classifinder/
> MCP server: https://pypi.org/project/classifinder-mcp/
>
> I'm a solo developer. Built the whole thing — engine, API, SDK, LangChain integration, MCP server, landing page. Happy to answer any questions about the architecture, detection patterns, or why I built this.

**Tips for HN:**
- Post between 8-10am ET on a weekday (Tuesday-Thursday)
- Reply to every comment personally and quickly
- Be honest about limitations (88 patterns vs GitGuardian's 550+, regex can't catch everything)
- Don't be defensive — acknowledge good criticisms
- The GitHub push protection anecdote is gold ("GitHub's own scanner flagged our pattern library")

---

### Day 1: Twitter/X Thread

**Why:** Developer Twitter is where the AI/LLM community lives. A thread gets reshared and bookmarked.

**What they care about:** Speed, simplicity, "just works," code snippets.

**Draft thread:**

> 1/ I built a secret scanner for the AI era. Not for Git — for LLM pipelines.
>
> One API call. Text in, clean text out. 88 secret types. Sub-5ms. Nothing stored.
>
> Free and open source: https://classifinder.tech
>
> 2/ The problem: secrets leak differently now.
>
> Users paste .env files into ChatGPT. RAG pipelines surface credentials. Agents hardcode API keys.
>
> Every scanner was built for Git repos. None of them give you an API that returns redacted text.
>
> 3/ ClassiFinder does one thing:
>
> POST your text → GET it back clean
>
> ```python
> from classifinder import ClassiFinder
> client = ClassiFinder(api_key="ss_live_...")
> result = client.redact("AWS_KEY=AKIAJGKJHSKLDJFH3284")
> print(result.redacted_text)
> # "AWS_KEY=[AWS_ACCESS_KEY_REDACTED]"
> ```
>
> 4/ LangChain integration — two lines:
>
> ```python
> from classifinder.integrations.langchain import ClassiFinderGuard
> chain = prompt | ClassiFinderGuard() | llm | output_parser
> ```
>
> Every prompt scanned and redacted before it hits the model.
>
> 5/ MCP server for Claude Code and Cursor:
>
> `pip install classifinder-mcp`
>
> Add to your agent config and your AI assistant can scan any text for secrets.
>
> 6/ What makes it different:
> - Never returns the full secret (masked preview only)
> - Numeric confidence scores (0.94, not "VERY_LIKELY")
> - Credit card detection with Luhn validation
> - The engine is open source — audit the code that touches your data
>
> 7/ Free tier: 60 req/min, 256KB payloads, all 82 detectors. No credit card.
>
> When I published the engine on GitHub, GitHub's own push protection flagged a Stripe test key in our pattern library. The scanner's test data triggered their scanner. 🤝
>
> Try it: https://classifinder.tech

---

### Day 1-2: Reddit

**r/LocalLLaMA** — The largest LLM developer community. They build local pipelines and care about preprocessing.

**Draft post:**

> **I built a free API that strips secrets from text before you send it to your LLM**
>
> If you're building RAG apps or agent pipelines, your users will eventually paste credentials into the input. ClassiFinder scans text for 88 types of secrets (AWS keys, Stripe keys, database passwords, etc.) and gives you back redacted text that's safe to forward to any model.
>
> One API call: `POST /v1/redact` → clean text back. Sub-5ms engine time. Nothing stored.
>
> Python SDK: `pip install classifinder`
> LangChain guard: `chain = prompt | ClassiFinderGuard() | llm`
> MCP server: `pip install classifinder-mcp`
>
> Free tier: 60 req/min. No credit card. Engine is open source.
>
> https://classifinder.tech
>
> Happy to answer questions about the architecture or how to integrate it.

**r/devops** — Secondary audience. They already know secret scanning but want hosted alternatives to CLI tools.

**Draft post:**

> **ClassiFinder: hosted secret scanning API with redaction, confidence scores, and a free tier (alternative to self-hosting Gitleaks/TruffleHog)**
>
> I built a lightweight API for secret detection that works on arbitrary text — not just Git repos. POST your text, get structured findings with confidence scores (0.0-1.0) and optionally redacted text.
>
> 88 secret types: AWS, GCP, Azure, Stripe, GitHub, GitLab, Slack, database connection strings, private keys, credit cards (Luhn-validated), OpenAI/Anthropic keys, and more.
>
> Designed for CI/CD pipelines, log scanning, and LLM preprocessing. Python SDK, LangChain integration, MCP server.
>
> Free: 60 req/min, 256KB payloads. Engine is open source.
>
> https://classifinder.tech
>
> Not trying to replace GitGuardian for Git scanning — this is for everything else.

---

### Week 2: Integration Communities

**LangChain Discord** — Post in #showcase or #tools. Focus on the `ClassiFinderGuard` integration.

**Message:**

> Built a LangChain guard that scans and redacts secrets from prompts before they hit the model. Two lines:
>
> ```python
> from classifinder.integrations.langchain import ClassiFinderGuard
> chain = prompt | ClassiFinderGuard() | llm | output_parser
> ```
>
> Catches 88 secret types (AWS keys, Stripe keys, database passwords, etc.). `fail_open=True` by default so your pipeline never breaks.
>
> `pip install classifinder[langchain]` — free tier, no credit card.
>
> https://pypi.org/project/classifinder/

**MCP community (GitHub discussions, Discord)** — The MCP server is a differentiator. No other secret scanner has one.

> Published an MCP server for secret scanning: `pip install classifinder-mcp`
>
> Two tools: `classifinder_scan` and `classifinder_redact`. Works with Claude Code, Cursor, Windsurf.
>
> Your agent can now scan any text for 88 types of leaked credentials and get back clean text.
>
> https://github.com/ThomasParas/classifinder-mcp

---

### Week 2-3: Product Hunt

**Why:** Less technical than HN but broader reach. Good for "building in public" narrative.

**Tagline:** "Secret scanning for the AI era"

**Description:** Keep it visual — show the demo, the before/after redaction, the detective dog.

---

### Month 2+: Content Marketing (SEO)

Blog posts, in priority order:

1. **"The $82,000 API Key: Why LLM Pipelines Need Secret Scanning"** — Hook story about a startup hit with an $82K bill after a leaked Google API key. Segue into ClassiFinder.

2. **"How to Prevent Secret Leaks in LangChain Pipelines"** — Tutorial. Shows the integration step by step. SEO target: "langchain secret scanning."

3. **"OWASP Says Scan Before You Send: What LLM02:2025 Means for Your Agent Pipeline"** — Compliance angle. OWASP elevated sensitive information disclosure to #2.

4. **"ClassiFinder vs GitGuardian vs Nightfall: Agent-First Secret Scanning"** — Comparison post. Honest about trade-offs. SEO target: "gitguardian alternative."

5. **"Every Secret Scanner Was Built for Git. Here's One Built for AI."** — Manifesto post. The founding story.

---

## Key Messages Per Audience

| Audience | What they care about | Lead with |
|----------|---------------------|-----------|
| AI/LLM developers | Speed, simplicity, pip install | LangChain integration, "two lines of code" |
| DevOps/platform | Accuracy, false positives, pricing | 88 patterns, confidence scores, usage-based pricing |
| Security engineers | Trust, open source, architecture | Open-source engine, no-storage architecture, Dockerfile |
| Compliance buyers | Control IDs, audit evidence | SOC 2 / PCI-DSS support, structured JSON logs |

---

## What NOT to Say

- Don't claim SOC 2 or PCI-DSS **certification** — say "supports compliance with"
- Don't say "catches all secrets" — say "88 known formats with high precision"
- Don't compare pattern count to GitGuardian (550+ vs 71) — compare on what matters (redaction, confidence scores, pricing model, LLM focus)
- Don't hide limitations — state them upfront and own them

---

## Assets Ready for Launch

| Asset | Status | Location |
|-------|--------|----------|
| Landing page | Live | https://classifinder.tech |
| API | Live | https://api.classifinder.tech |
| Python SDK | Live (v0.1.2) | PyPI: `classifinder` |
| MCP server | Live (v0.1.0) | PyPI: `classifinder-mcp` |
| Open-source engine | Live | github.com/ThomasParas/classifinder-engine |
| Privacy Policy | Live | classifinder.tech/privacy-policy.html |
| Terms of Service | Live | classifinder.tech/terms-of-service.html |
| Pattern library doc | Ready | `docs/pattern-library.md` |
| Hard questions + answers | Ready | `docs/hard-questions.md` |
| Disclaimer text | Ready | `docs/disclaimer.md` |
| Marketing strategy | Ready | `docs/classifinder-marketing-strategy.md` |
| End-to-end test flow | Ready | `docs/test-flow.md` |
| Detective dog mascot | Ready | `classifinder-site/assets/` |

---

## Launch Day Checklist

```
[ ] Run the full end-to-end test flow (docs/test-flow.md)
[ ] Verify landing page form creates a real key
[ ] Verify demo form uses /v1/demodemo (no hardcoded key)
[ ] Post Show HN (8-10am ET, Tue-Thu)
[ ] Post Twitter thread
[ ] Post r/LocalLLaMA
[ ] Post r/devops
[ ] Monitor HN comments — reply to every one
[ ] Monitor API health during traffic spike
```
