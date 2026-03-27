# ClassiFinder — Marketing Strategy & Competitive Positioning

---

## The One-Liner

ClassiFinder is the secret scanner built for the AI era — a stateless API that strips credentials from text before it reaches your LLM, your logs, or your users.

---

## Core Positioning

Every competitor in this space was built for the DevOps era. GitGuardian scans Git repos. TruffleHog crawls commit histories. GitHub Advanced Security watches pull requests. They all assume your code lives in a repository and your secrets leak through commits.

That's not how secrets leak anymore.

In 2026, secrets leak when a user pastes their .env file into ChatGPT. When a RAG pipeline ingests a config file and surfaces credentials in a response. When an AI coding agent hardcodes an API key into generated code. When a customer support bot receives a database connection string in a ticket and logs it to Datadog.

ClassiFinder is built for this world. One API call. Text in, findings out, redacted text back. No Git required. No dashboard. No incident management workflow. Just clean, safe text — ready to send to your model.

---

## Competitive Gaps We Fill

### 1. GitGuardian returns full secret values. We don't.

GitGuardian's /v1/scan endpoint returns the complete secret in the `match` field. If their response is logged, cached, or intercepted, the actual secret is exposed. Our API returns `value_preview` — a masked version showing only the first and last 4 characters. This isn't a limitation, it's a deliberate security decision. If you're building a tool that handles other people's secrets, you should never hold more than you need.

**Marketing angle:** "The only secret scanner that doesn't become a secret leak."

### 2. GitGuardian doesn't offer redaction. Nightfall does, but at enterprise pricing.

GitGuardian's scan API returns findings — it tells you what it found and where. But it doesn't give you a clean version of the text with secrets stripped out. If you need redacted text (and every LLM middleware does), you have to build that yourself.

Nightfall offers native redaction, but their pricing is enterprise-focused and opaque. You can't see what it costs without talking to sales.

ClassiFinder's /redact endpoint returns redacted text on the free tier. One call, and you get text that's safe to forward to any model.

**Marketing angle:** "POST your text. GET it back clean. That's the whole API."

### 3. Everyone charges per developer seat. We charge per request.

GitHub Advanced Security: $19/active committer/month. GitLab Ultimate: $29/user/month. Snyk: $25/developer/month. These pricing models were designed for human engineering teams with headcount.

If you're running an AI agent that scans 500,000 text blocks per day, "per developer seat" pricing makes no sense. You're not a developer. You're a pipeline.

ClassiFinder charges per request. Free tier: 10,000 calls/month. Starter: $19/month for 200,000 calls. Pro: $49/month for 1,000,000 calls. The cost scales with your usage, not your team size.

**Marketing angle:** "Pricing that makes sense for agents, not just engineers."

### 4. No one returns numeric confidence scores from a scan API.

GitGuardian returns a binary validity check (valid / invalid / cannot_check). Nightfall returns categorical confidence (VERY_UNLIKELY through VERY_LIKELY). Neither gives you a number your agent can threshold on.

ClassiFinder returns a float from 0.0 to 1.0. Your agent can decide: block the request if confidence > 0.8, flag for review if 0.5-0.8, pass through if below 0.5. Programmatic decision-making requires numeric precision, not categories.

**Marketing angle:** "Confidence scores your code can actually use."

### 5. No one has published LangChain/LlamaIndex integrations for secret scanning.

Both Grok and Gemini independently confirmed: zero production-quality packages exist for secret scanning inside LangChain, LlamaIndex, CrewAI, or AutoGen as of March 2026. Developers are writing custom regex filters or piping text through CLI tools via subprocess.

ClassiFinder will ship with `pip install classifinder` including a LangChain callback handler and a LlamaIndex tool wrapper. One import, and every prompt your agent sends is scanned and redacted automatically.

**Marketing angle:** "Two lines of code to make your agent pipeline leak-proof."

```python
from classifinder.integrations.langchain import ClassiFinderGuard
chain = prompt | ClassiFinderGuard() | llm | output_parser
```

### 6. Self-hosting open-source alternatives is harder than it looks.

A developer can wrap Betterleaks or Gitleaks in a FastAPI server and deploy it on Lambda. In theory. In practice, they're running a Go binary via subprocess inside a Python container on serverless infrastructure. Cold starts hit 1-3 seconds. There's no redaction, no confidence scores, no structured JSON output, no rate limiting, no auth. Every detector update requires redeploying the container.

ClassiFinder is sub-50ms, zero-ops, always up to date.

**Marketing angle:** "You could self-host Gitleaks on Lambda. But you won't enjoy it."

---

## OWASP Compliance Messaging

The OWASP Top 10 for Large Language Models (2025 edition) provides direct validation for our product:

**LLM02:2025 — Sensitive Information Disclosure** (ranked #2, up from #6):
OWASP specifically recommends "tokenization and redaction using pattern matching" to prevent sensitive data from entering models. Our /redact endpoint is literally this recommendation implemented as a service.

**LLM07:2025 — System Prompt Leakage** (brand new category in 2025):
OWASP explicitly states: "Avoid embedding any sensitive information (e.g., API keys, auth keys, database names) directly in the system prompts." ClassiFinder can scan system prompts before deployment to catch embedded credentials.

**Landing page copy:**
"ClassiFinder implements OWASP LLM02 and LLM07 mitigations out of the box. Add one API call to your pipeline and check the compliance box."

---

## Compliance & Audit Messaging

Enterprise buyers don't choose security tools because they're cool. They choose them because an auditor told them to. These are the specific control IDs we help satisfy:

**SOC 2 Type II:**
- CC6.1 / CC6.6 / CC6.7 — Logical access controls. ClassiFinder demonstrates proactive detection of leaked credentials across data pipelines.
- CC7.1 / CC7.2 / CC7.4 — System operations, monitoring, incident response. Our structured JSON findings + metadata logs provide auditable evidence of continuous scanning.

**PCI-DSS 4.0 (mandatory since March 2025):**
- Requirement 3 — Protect stored account data. ClassiFinder discovers unencrypted credentials and connection strings.
- Requirement 8.6.3 — Explicitly requires that passwords and passphrases are not hardcoded in scripts, configuration files, or source code. Our CI/CD integration proves compliance.
- Requirement 6 — Secure systems. Requirement 10 — Monitoring.

**Landing page copy:**
"Satisfy SOC 2 CC6.7, CC7.1, and PCI-DSS Requirements 3 & 8 with auditable scan logs and redaction evidence."

---

## Threat Narrative (for blog posts and landing page)

The data points below are from GitGuardian's 2026 State of Secrets Sprawl Report, Grok/Gemini research (March 2026), and OWASP:

- AI-service secrets (keys for OpenAI, Anthropic, Google Gemini) increased 81% year-over-year in 2025
- 23.8–29 million new secrets appeared on public GitHub repos in 2024–2025, with 70% still active
- In February 2026, 149 million credentials were found exposed in an unsecured database
- LangChain CVE-2025-68664 ("LangGrinch") allowed credential exfiltration via prompt serialization
- CrewAI had a GitHub token exposure vulnerability in 2025
- A startup was hit with an $82,000 bill in 48 hours after a Google API key (now valid for Gemini) was leaked publicly
- Samsung banned ChatGPT internally after engineers pasted proprietary code and credentials into the interface
- 22% of cloud security incidents are caused by weak secrets management (Cycode, Dec 2025)
- OWASP elevated Sensitive Information Disclosure to #2 on the LLM Top 10 in 2025, up from #6

- When we open-sourced ClassiFinder's pattern library on GitHub, GitHub's own push protection blocked the commit — it flagged a Stripe test key (`sk_test_...`) in our known_test_values set. Our secret scanner's test data triggered their secret scanner. Proof the detection works.

**Blog post titles this data supports:**
- "Your AI Agent Has a Secret Problem (Literally)"
- "The $82,000 API Key: Why LLM Pipelines Need Secret Scanning"
- "OWASP Says Scan Before You Send: What LLM02:2025 Means for Your Agent Pipeline"
- "Every Secret Scanner Was Built for Git. Here's One Built for AI."

---

## Target Audiences (in priority order)

### 1. AI Agent / LLM App Developers (Primary)

Building wrappers, RAG apps, chatbots, or autonomous agents. They handle user-submitted text that may contain secrets. They need a fast, simple API to scan and redact before sending to a model.

**Where to reach them:** r/LocalLLaMA, r/LangChain, LangChain/LlamaIndex Discord servers, Hacker News, X/Twitter AI dev community, AI newsletters (The Batch, TLDR AI)

**What they care about:** Latency, simplicity, free tier, pip install, "just works"

### 2. Platform Engineering / DevOps (Secondary)

Need lightweight CI/CD secret scanning without paying enterprise platform taxes. Already using GitLeaks or TruffleHog but want a hosted option for non-Git workflows.

**Where to reach them:** r/devops, r/devsecops, Hacker News, GitHub Marketplace, VS Code Marketplace

**What they care about:** Accuracy, false positive rates, GitHub Action integration, usage-based pricing

### 3. Compliance-Driven B2B (Tertiary, highest revenue)

Startups going through their first SOC 2 audit. Mid-market companies with PCI-DSS requirements. They need to prove they scan for hardcoded secrets and have evidence.

**Where to reach them:** Direct outreach, content marketing ("How to pass SOC 2 secret scanning requirements"), partnerships with compliance consultants

**What they care about:** Audit evidence, specific control IDs, enterprise features, SLAs

---

## Launch Channels

**Week 1: Foundation**
- Product Hunt launch
- Hacker News "Show HN" post
- r/LocalLLaMA, r/devops, r/netsec, r/programming posts
- X/Twitter announcement thread

**Week 2-4: Integration Play**
- Publish `pip install classifinder` with LangChain callback handler
- Publish GitHub Action (`classifinder/scan-action@v1`)
- Submit to LangChain community tools directory
- Post on LangChain and LlamaIndex Discord servers

**Month 2-3: Content**
- Blog: "How to Prevent Secret Leaks in LLM Pipelines" (SEO target)
- Blog: "ClassiFinder vs GitGuardian vs Nightfall: Agent-First Secret Scanning"
- Blog: "OWASP LLM02 Compliance with One API Call"
- Documentation site with interactive examples (try scanning sample text in-browser)

**Ongoing: Community**
- Respond to every GitHub issue and false positive report
- Maintain a public changelog of new secret types added
- Publish monthly "Secrets in the Wild" data from anonymized aggregate scan stats (types detected, not values)

---

## Key Differentiators Summary

| Feature | ClassiFinder | GitGuardian | Nightfall | Betterleaks (OSS) |
|---|---|---|---|---|
| Raw text API | Yes (core product) | Yes (secondary) | Yes (core) | No (CLI only) |
| Redacted text output | Yes, free tier | No | Yes, enterprise | No |
| Confidence score | Numeric 0.0-1.0 | Binary validity | Categorical | No |
| Returns full secret | Never (masked preview) | Yes (full value) | Configurable | N/A (CLI output) |
| Pricing model | Per request | Per seat/committer | Per data volume | Free (self-host) |
| Latency | <50ms | Unknown | ~100-500ms | Fast (local) |
| LangChain integration | Yes (planned) | Experimental MCP | No | No |
| Target audience | AI agents & pipelines | Security teams | Enterprise DLP | Developers |
| Secret types | 50 (launch), growing | 550+ | 150+ | 160+ |
| Free tier | 10,000 calls/month | 10,000 calls/month | 3 GB/month | Unlimited (self-host) |

---

## Detection Coverage (50 Secret Types)

Publish this list on the landing page. It builds trust, answers the buyer's first question ("does it catch what I care about?"), and is SEO-rich for searches like "detect OpenAI API key leak."

### Cloud Providers (9)
- AWS Access Key ID (`AKIA...`)
- AWS Secret Access Key
- GCP API Key / Google AI Gemini Key (`AIza...`)
- GCP Service Account Key (JSON private_key block)
- Azure Storage Account Key
- Azure AD Client Secret
- DigitalOcean Personal Access Token (`dop_v1_...`)
- Heroku API Key
- Cloudflare API Token

### Payment & Financial (8)
- Stripe Live Secret Key (`sk_live_...`)
- Stripe Test Secret Key (`sk_test_...`)
- Stripe Live Publishable Key (`pk_live_...`)
- Stripe Webhook Signing Secret (`whsec_...`)
- Stripe Restricted API Key (`rk_live_...`)
- PayPal Client Secret
- Square Access Token (`EAA...`)
- Credit Card Numbers (Visa, Mastercard, Amex, Discover — Luhn-validated)

### Version Control & CI/CD (9)
- GitHub Personal Access Token — Classic (`ghp_...`)
- GitHub Fine-Grained PAT (`github_pat_...`)
- GitHub OAuth App Client Secret (`gho_...`)
- GitHub App Installation Token (`ghs_...`)
- GitHub User-to-Server Token (`ghu_...`)
- GitLab Personal Access Token (`glpat-...`)
- GitLab Pipeline Trigger Token (`glptt-...`)
- Bitbucket App Password
- CircleCI API Token

### Communications & SaaS (9)
- Slack Bot Token (`xoxb-...`)
- Slack User Token (`xoxp-...`)
- Slack Incoming Webhook URL
- Twilio Account SID (`AC...`)
- Twilio Auth Token
- SendGrid API Key (`SG....`)
- Mailgun API Key (`key-...`)
- Discord Bot Token
- Telegram Bot Token

### Database & Infrastructure (7)
- PostgreSQL Connection String (with password)
- MySQL Connection String (with password)
- MongoDB Connection String (with password)
- Redis Connection String (with password)
- Password Embedded in URL (`https://user:pass@host`)
- Database Password in .env (`DB_PASSWORD=...`, `POSTGRES_PASSWORD=...`)
- SSH/RSA/EC/DSA Private Keys (PEM blocks)

### AI / LLM Providers (3)
- OpenAI API Key (`sk-...`, `sk-proj-...`)
- Anthropic API Key (`sk-ant-...`)
- Cohere API Key

### Generic & Auth Tokens (5)
- JSON Web Token (JWT) (`eyJ...`)
- Bearer Token in Authorization Header
- Basic Auth Credentials in Header
- Generic API Key in .env (`API_KEY=...`, `SECRET_KEY=...`, etc.)
- Generic High-Entropy String (context-dependent catch-all)

**Landing page copy:**
"50 secret types across 7 categories. Cloud keys, payment credentials, database passwords, private keys, AI provider tokens, and more. See the full list."

---

## Legal: Terms of Service and Disclaimers

Three documents needed before launch. Non-negotiable.

### 1. Terms of Service

Must include:
- **Limitation of liability** — ClassiFinder's liability capped at the amount the user paid (free tier = $0). This is standard for every security tool.
- **Warranty disclaimer** — Service provided "as-is." No guarantee of catching every secret. No guarantee of uptime.
- **Acceptable use** — Users must not use the API to process data they don't have rights to, or to test stolen credentials.
- **Right to revoke access** — We can revoke API keys for abuse.
- **Data handling commitment** — We do not store, log, or retain request bodies. Only metadata is logged.

**How to get one:** Use Termly or iubenda ($50-100/year) to generate a SaaS ToS, then have a lawyer review it. Do not launch without this.

### 2. Privacy Policy

Must cover:
- **What we collect** — Email address (for key provisioning), API key hash (for auth), request metadata (for billing/ops). That's it.
- **What we do NOT collect** — Request bodies, response bodies, secret values, finding details, user content of any kind.
- **No-storage architecture** — Explicitly state that text submitted to /scan and /redact is processed in memory and discarded. Nothing is written to disk, database, or logs.
- **Third parties** — Turso stores only key hashes and emails, not user content. Fly.io hosts the infrastructure.

### 3. API Disclaimer

Short text for the API docs, landing page footer, and Swagger UI description:

> ClassiFinder is a detection aid, not a guarantee. While we work to maintain accurate and comprehensive secret detection, no scanner catches 100% of secrets in 100% of formats. ClassiFinder should be used as one layer of a defense-in-depth security strategy, not as a sole safeguard. By using this service, you acknowledge that ClassiFinder is provided "as-is" without warranty of any kind. See our Terms of Service for full details.

This text should appear:
- On the landing page footer
- In the API docs (Swagger UI description)
- In the Python SDK README
- In the Terms of Service as a referenced clause
