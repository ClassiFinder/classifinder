# Pattern Expansion Spec — 101 → ~300 Patterns

**Status:** Ready for implementation
**Source:** TruffleHog competitor research (`classifinder-temp/trufflehog-research-findings.md`)
**Goal:** Add ~200 patterns with distinctive token formats from TruffleHog's 866 detectors

---

## How This Repo Works

ClassiFinder is a stateless secret scanner API. The engine is at `app/engine/`. Patterns are defined as `SecretPattern` dataclass instances in `app/engine/patterns/`, registered via `register()`, and the scanner runs them all against input text.

**This document is self-contained.** An agent should be able to read this file alone and execute the expansion.

---

## Step-by-Step Process for Each Pattern

### 1. Research the token format

Before writing any code, verify the provider's current token format. TruffleHog's regex (in Go) is a starting point, but formats change. For each provider:

- Search the web for `"<provider> API key format"` or check their docs
- Check TruffleHog's detector at `classifinder-temp/trufflehog/pkg/detectors/<provider>/` if the repo is available
- Identify: **prefix** (e.g., `sk-`, `ghp_`, `xoxb-`), **character set** (hex, alphanumeric, base64), **length** (fixed or range), **separators** (dots, hyphens)
- Determine if the pattern is **prefix-anchored** (high confidence, no entropy check needed) or **context-dependent** (needs keyword anchoring and entropy threshold)

### 2. Write the SecretPattern definition

Add to the appropriate file in `app/engine/patterns/`:
- `ai.py` — AI/ML providers
- `cloud.py` — Cloud, CI/CD, IaC, identity
- `comms.py` — Communication, SaaS, monitoring
- `payment.py` — Payment, crypto, financial
- `vcs.py` — Version control, package registries
- `database.py` — Database connection strings, infra
- `generic.py` — Catch-all patterns (rarely needs new entries)

**Template for prefix-anchored patterns** (high confidence):
```python
PROVIDER_API_KEY = SecretPattern(
    id="provider_api_key",
    name="Provider API Key",
    description="Provider API key with prov_ prefix. Grants access to Provider services.",
    provider="provider",
    severity="critical",  # or "high", "medium", "low"
    regex=re.compile(
        r"(?P<secret>prov_[A-Za-z0-9]{32,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # prefix is distinctive enough
    context_keywords=["provider", "PROVIDER_API_KEY", "provider_key"],
    known_test_values=set(),
    recommendation="Revoke this key at provider.com under Settings > API Keys.",
    tags=["category", "provider"],
)
```

**Template for context-dependent patterns** (lower confidence, needs keyword anchoring):
```python
PROVIDER_API_KEY = SecretPattern(
    id="provider_api_key",
    name="Provider API Key",
    description=(
        "Provider API key, a 32-character hex string."
        " Detected when preceded by Provider-specific context keywords."
    ),
    provider="provider",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:PROVIDER_API_KEY|PROVIDER_KEY|provider.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["provider", "PROVIDER_API_KEY", "provider_key"],
    known_test_values=set(),
    recommendation="Revoke this key at provider.com under Settings > API Keys.",
    tags=["category", "provider"],
)
```

**Key rules:**
- Regex MUST have a named capture group `(?P<secret>...)`
- Regex MUST end with a negative lookahead `(?![allowed_chars])` to prevent partial matches
- `id` must be unique, lowercase, snake_case
- `severity`: "critical" = direct financial/data access, "high" = significant access, "medium" = limited access, "low" = informational
- `confidence_base`: 0.95+ for prefix-anchored, 0.70-0.85 for context-dependent
- `entropy_threshold`: 0.0 for prefix-anchored, 3.0-3.5 for context-dependent hex, 4.0+ for truly generic
- `context_keywords`: lowercase, include env var names, provider name, common aliases
- `recommendation`: always include WHERE to revoke (URL or dashboard path)

### 3. Register the pattern

Add the pattern constant to the `register()` call at the bottom of the file:
```python
register(
    ...,
    PROVIDER_API_KEY,  # add here
)
```

### 4. Add test cases to the harness

Add an entry to `tests/pattern_test_cases.py`:
```python
"provider_api_key": {
    "positives": [
        "PROVIDER_API_KEY=prov_AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        'export PROVIDER_KEY="prov_ZyXwVuTsRqPoNmLkJiHgFeDcBa987654"',
    ],
    "negatives": [
        "prov_short",  # too short
        "provX_AbCdEfGhIjKlMnOpQrStUvWxYz123456",  # wrong prefix
    ],
    "min_confidence": 0.90,  # or 0.30 for context-dependent
},
```

**Test data rules:**
- Positive values MUST match the regex exactly (correct length, charset, prefix)
- Negative values MUST NOT match (wrong prefix, too short, missing context)
- Never use real secrets — use character patterns like `AbCdEfGh...`
- Verify lengths match the regex quantifiers exactly
- For context-dependent patterns, positives must include the context keyword
- Set `min_confidence` to 0.10 if the pattern has known_test_values that overlap with your sample

### 5. Sync to classifinder-engine/

Copy the modified pattern file to the standalone engine:
```bash
cp app/engine/patterns/<file>.py ../../classifinder-engine/patterns/<file>.py
```

### 6. Run tests

```bash
# Pattern harness (catches missing tests, false positives, collisions)
python -m pytest tests/test_pattern_harness.py -v

# Full suite (must stay green)
python -m pytest tests/ -v

# Engine tests
cd ../../classifinder-engine && python -m pytest tests/ -v
```

### 7. Update documentation

- Add the pattern to `docs/pattern-library.md`
- Update pattern count in root `CLAUDE.md` and `classifinder/CLAUDE.md`

---

## Patterns Already Implemented (101)

Do NOT re-add these. Check this list before starting any new pattern.

**AI/ML (13):** openai_api_key, anthropic_api_key, cohere_api_key, huggingface_token, replicate_api_token, groq_api_key, deepseek_api_key, xai_api_key, elevenlabs_api_key, assemblyai_api_key, deepgram_api_key, langfuse_secret_key, mistral_api_key

**Cloud/Infra (22):** aws_access_key, aws_secret_key, gcp_api_key, gcp_service_account_key, azure_storage_key, azure_ad_client_secret, digitalocean_token, heroku_api_key, cloudflare_api_token, doppler_token, terraform_cloud_token, vault_token, pulumi_access_token, fly_api_token, alibaba_access_key, vercel_access_token, vercel_refresh_token, netlify_token, ibm_cloud_api_key, okta_api_token, buildkite_token, railway_token

**Communication/SaaS (25):** slack_bot_token, slack_user_token, slack_webhook_url, twilio_account_sid, twilio_auth_token, sendgrid_api_key, mailgun_api_key, discord_bot_token, telegram_bot_token, newrelic_admin_api_key, newrelic_insights_key, newrelic_user_api_key, grafana_api_key, linear_api_key, notion_api_key, sentry_org_token, sentry_user_token, datadog_api_key, datadog_app_key, pagerduty_api_key, figma_pat, auth0_management_token, discord_webhook_url, teams_webhook_url, mattermost_token

**Payment (14):** stripe_live_secret_key, stripe_test_secret_key, stripe_live_publishable_key, stripe_webhook_secret, stripe_restricted_key, paypal_client_secret, square_access_token, credit_card_number, shopify_access_token, shopify_custom_token, shopify_private_token, ethereum_private_key, bitcoin_wif_key, razorpay_key

**VCS/CI/Registries (14):** github_pat_classic, github_pat_fine_grained, github_oauth_secret, github_app_installation_token, github_user_to_server_token, gitlab_pat, gitlab_pipeline_trigger, bitbucket_app_password, circleci_token, npm_token, pypi_token, rubygems_token, airtable_api_key, nuget_api_key

**Database/Infra (8):** postgres_connection_string, mysql_connection_string, mongodb_connection_string, redis_connection_string, password_in_url, env_database_password, ssh_private_key, supabase_service_key

**Generic (5):** jwt_token, bearer_token, basic_auth_header, generic_api_key_env, generic_high_entropy

---

## Patterns to Add (~200)

Organized into 6 batches. Each batch can be implemented independently. Within each batch, providers are listed roughly by priority (most common/impactful first).

**Important:** Token formats below are from TruffleHog's Go regex as of April 2026. Verify each one against the provider's current docs before implementing. Formats change.

### Batch 1: Crypto & Blockchain (~30)

| Provider | TruffleHog Detector | Expected Format | Priority |
|----------|-------------------|-----------------|----------|
| coinbase | `coinbase/` | UUID key name + EC PEM private key (complex) | High |
| kraken | `kraken/` | Base64, 56+ chars, context-dependent | High |
| binance | `binance/` | 64-char alphanumeric, context-dependent | High |
| kucoin | `kucoin/` | UUID + passphrase + secret, multi-part | Medium |
| etherscan | `etherscan/` | 34-char alphanumeric, context-dependent | Medium |
| polygon | `polygon/` | 32-char alphanumeric, context-dependent | Medium |
| infura | `infura/` | 32-char hex project ID, context-dependent | Medium |
| alchemy | `alchemy/` | 32-char alphanumeric, context-dependent | Medium |
| moralis | `moralis/` | Alphanumeric, context-dependent | Low |
| blocknative | `blocknative/` | UUID format, context-dependent | Low |
| coinapi | `coinapi/` | UUID format, context-dependent | Low |
| cryptocompare | `cryptocompare/` | 64-char hex, context-dependent | Low |
| bscscan | `bscscan/` | 34-char alphanumeric | Low |
| poloniex | `poloniex/` | UUID + secret pair | Low |
| bitfinex | `bitfinex/` | Alphanumeric, context-dependent | Low |
| bitmex | `bitmex/` | 24-char alphanumeric | Low |
| coinlayer | `coinlayer/` | 32-char alphanumeric | Low |
| luno | `luno/` | Alphanumeric pair | Low |
| oanda | `oanda/` | Alphanumeric, context-dependent | Low |
| cexio | `cexio/` | Alphanumeric, context-dependent | Low |

### Batch 2: Enterprise SaaS (~35)

| Provider | TruffleHog Detector | Expected Format | Priority |
|----------|-------------------|-----------------|----------|
| atlassian | `atlassian/` | API token, 24-char alphanumeric | High |
| jira | `jiratoken/` | Email + token + domain (multi-part) | High |
| asana | `asanapersonalaccesstoken/` | `0/` prefix + 32-char hex | High |
| monday | `monday/` | `eyJ` JWT prefix (like auth0) | Medium |
| clickup | `clickuppersonaltoken/` | `pk_` prefix + 32-char | Medium |
| hubspot | `hubspot/` | `pat-` prefix variants | Medium |
| zendesk | `zendeskapi/` | 40-char alphanumeric, context-dependent | Medium |
| freshdesk | `freshdesk/` | Alphanumeric, context-dependent | Medium |
| intercom | `intercom/` | 60-char alphanumeric, context-dependent | Medium |
| postman | `postmanapi/` | `PMAK-` prefix | High |
| launchdarkly | `launchdarkly/` | `api-` prefix + UUID | Medium |
| snyk | `snyk/` | UUID format, context-dependent | Medium |
| sonarcloud | `sonarcloud/` | 40-char alphanumeric, context-dependent | Low |
| confluent | `confluent/` | Key + secret pair | Medium |
| hasura | `hasura/` | Domain + admin secret | Medium |
| jumpcloud | `jumpcloud/` | 40-char hex, context-dependent | Low |
| onelogin | `onelogin/` | Client ID + secret pair | Low |
| databricks | `databrickstoken/` | `dapi` prefix + 32-char hex | High |
| snowflake | `snowflake/` | JWT or password, context-dependent | Medium |
| tableau | `tableau/` | Token name + secret + endpoint (multi-part) | Low |
| contentful | `contentful/` | `CFPAT-` prefix | Medium |
| graphcms | `graphcms/` | `eyJ` JWT, context-dependent | Low |

### Batch 3: Communication & Social (~25)

| Provider | TruffleHog Detector | Expected Format | Priority |
|----------|-------------------|-----------------|----------|
| messagebird | `messagebird/` | `live_` prefix + 25-char | Medium |
| nexmo/vonage | `nexmo/` | 8-char API key + 16-char secret | Medium |
| ringcentral | `ringcentral/` | Alphanumeric, context-dependent | Low |
| sendbird | `sendbird/` | 40-char hex, context-dependent | Low |
| twitch | `twitchaccesstoken/` | Client ID + secret pair | Medium |
| twitter | `twitterconsumerkey/` | 25-char alphanumeric + secret | Medium |
| spotify | `spotify/` | Client ID + secret (both 32-char hex) | Medium |
| facebook | `facebookoauth/` | Long numeric token, context-dependent | Low |
| instagram | `instagram/` | Long alphanumeric, context-dependent | Low |
| youtube | (uses GCP API key) | Already covered by gcp_api_key | Skip |
| mailerlite | `mailerlite/` | 32-char alphanumeric, context-dependent | Low |
| sendinblue | `sendinblue/` | `xkeysib-` prefix + 64-char | Medium |
| elasticemail | `elasticemail/` | UUID format, context-dependent | Low |
| d7network | `d7network/` | Alphanumeric, context-dependent | Low |
| gitter | `gitter/` | 40-char hex, context-dependent | Low |
| zulipchat | `zulipchat/` | API key + user ID + domain (multi-part) | Low |
| webex | `webex/` | Bearer token, context-dependent | Low |
| front | `front/` | `Bearer ` + JWT, context-dependent | Low |

### Batch 4: Developer Tools & CI/CD (~25)

| Provider | TruffleHog Detector | Expected Format | Priority |
|----------|-------------------|-----------------|----------|
| saucelabs | `saucelabs/` | 36-char UUID, context-dependent | Medium |
| browserstack | `browserstack/` | 20-char alphanumeric, context-dependent | Medium |
| travisci | `travisci/` | 22-char alphanumeric, context-dependent | Medium |
| droneci | `droneci/` | Long alphanumeric, context-dependent | Low |
| render | `render/` | `rnd_` prefix + alphanumeric | Medium |
| codemagic | `codemagic/` | Alphanumeric, context-dependent | Low |
| cloudflarecakey | `cloudflarecakey/` | `v1.0-` prefix | Medium |
| scaleway | `scalewaykey/` | UUID, context-dependent | Low |
| linode | `linode/` | 64-char hex, context-dependent | Medium |
| vultr | `vultr/` | Alphanumeric, context-dependent | Low |
| portainer | `portainer/` | JWT, context-dependent | Low |
| harness | `harness/` | Various formats | Low |
| docker | `dockerhub/` | UUID or `dckr_pat_` prefix | Medium |
| packagecloud | `packagecloud/` | 40-char hex, context-dependent | Low |
| codecov | `codecov/` | UUID, context-dependent | Low |
| sentry DSN | `sentrydsn/` | `https://...@sentry.io/...` URL format | Medium |
| newrelic browser | `newrelicpersonalapikey/` | `NRRA-` prefix | Medium |
| honeycomb | `honeycomb/` | Alphanumeric, context-dependent | Medium |
| logdna | `logdna/` | 32-char hex, context-dependent | Low |
| papertrail | `papertrail/` | Alphanumeric, context-dependent | Low |

### Batch 5: Cloud Provider Extensions (~20)

| Provider | TruffleHog Detector | Expected Format | Priority |
|----------|-------------------|-----------------|----------|
| azure_batch | `azurebatch/` | 88-char base64 key, context-dependent | Medium |
| azure_search | `azuresearchadminkey/` | 52-char base64, context-dependent | Medium |
| azure_cosmos | `cosmosdbkey/` | 88-char base64, context-dependent | Medium |
| azure_devops | `azuredevopspersonalaccesstoken/` | 52-char base64, context-dependent | Medium |
| azure_sas | `azuresastoken/` | URL with `sig=` parameter | Medium |
| aws_mws | `amazonmws/` | MWS auth token, context-dependent | Low |
| gcp_oauth | (multiple) | OAuth refresh tokens, context-dependent | Low |
| oracle_cloud | `oci/` | OCI-specific formats | Low |
| tencent_cloud | `tencentcloud/` | `AKID` prefix | Medium |
| yandex_cloud | `yandex/` | Various formats | Low |
| huawei_cloud | `huaweicloud/` | `AK` prefix variants | Low |

### Batch 6: Long Tail (~65)

Everything else from TruffleHog's detector list that has a semi-distinctive format. Lower priority, add as time permits. See `classifinder-temp/trufflehog-research-findings.md` for the full gap list by category.

---

## Execution Strategy

### Recommended approach: batch by category

1. Pick a batch (e.g., Batch 2: Enterprise SaaS)
2. Research all token formats in the batch (web search per provider)
3. Implement all patterns in one branch
4. Run full test suite once at the end
5. Sync engine, commit, push
6. Update pattern count in docs

### Parallelization

Multiple agents can work on different batches simultaneously IF they own separate pattern files:
- Agent A: `ai.py` (Batch 1 crypto patterns could go here or a new `crypto.py`)
- Agent B: `comms.py` (Batch 3)
- Agent C: `cloud.py` (Batch 5)

If a batch spans multiple files, one agent should own the whole batch.

### When to create a new pattern file

If a category gets too large (>30 patterns), split it. For example:
- `crypto.py` for crypto/blockchain (from `payment.py`)
- `identity.py` for Auth0, Okta, OneLogin, JumpCloud (from `cloud.py`)
- `monitoring.py` for Datadog, New Relic, Sentry, PagerDuty, Grafana, Honeycomb (from `comms.py`)

When creating a new file:
1. Create `app/engine/patterns/<newfile>.py` with the same structure as existing files
2. Add `from .patterns import newfile  # noqa: F401` to `scanner.py` imports
3. Copy to `classifinder-engine/patterns/`

### Known gotchas

- **DeepSeek/OpenAI overlap:** Both use `sk-` prefix. OpenAI's broader regex wins dedup. If adding more `sk-` providers, they'll hit the same issue. Consider whether context-anchoring is sufficient.
- **Hex patterns without prefix:** 32-char hex strings (MD5-length) are VERY common in non-secret contexts. Always require context keywords for these. Never use confidence > 0.80 for context-dependent hex patterns.
- **Multi-part credentials:** ClassiFinder doesn't support correlating ID + secret across a text span. For multi-part providers (AWS ID+secret, Jira email+token+domain), detect each part independently.
- **Engine sync:** After modifying any file in `app/engine/`, copy it to `classifinder-engine/`. The pre-commit hook checks this.
- **Test harness coverage:** The `test_pattern_harness.py` test `test_all_patterns_have_test_cases` will FAIL if you add a pattern without either adding it to `pattern_test_cases.py` or adding it to the `HARNESS_EXEMPT` set. This is intentional — it forces test coverage.
- **FP wordlist:** If your positive test samples contain substrings like "example", "test", "sample", etc., the FP wordlist will penalize them. Use random-looking character patterns like `AbCdEfGh...` instead.
