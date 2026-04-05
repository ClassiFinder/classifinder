# Pattern Expansion Plan — ClassiFinder

**Created:** 2026-04-01
**Status:** ALL 3 BATCHES COMPLETE — 50 → 88 patterns shipped
**Source:** secrets-patterns-db (1,610 patterns, CC-BY-4.0) at `classifinder-temp/secrets-patterns-db/`

## Batch 1 Completion Log (2026-04-01)

**Result:** 50 → 71 patterns. All tests green.

**21 patterns added:**
- **ai.py** (+3): `huggingface_token`, `replicate_api_token`, `groq_api_key`
- **cloud.py** (+6): `doppler_token`, `terraform_cloud_token`, `vault_token`, `pulumi_access_token`, `fly_api_token`, `alibaba_access_key`
- **comms.py** (+6): `newrelic_admin_api_key`, `newrelic_insights_key`, `newrelic_user_api_key`, `grafana_api_key`, `linear_api_key`, `notion_api_key`
- **payment.py** (+3): `shopify_access_token`, `shopify_custom_token`, `shopify_private_token`
- **vcs.py** (+3): `npm_token`, `pypi_token`, `rubygems_token`

**Deviations from plan:**
- Doppler regex widened from `{43}` to `{40,44}` per official Doppler docs (`dp.pt.` tokens vary 40-44 chars)
- `newrelic_rest_api_key` (NRRA- prefix) **replaced** with `newrelic_user_api_key` (NRAK- prefix) — NRRA doesn't exist in any official New Relic docs; NRAK is the verified user API key format with 27 lowercase alphanumeric chars
- Google AI/Gemini (pattern #3) deferred to Batch 2 — overlaps with existing `gcp_api_key` (same AIza prefix), needs context-based disambiguation

**What was shipped:**
- Pattern code in classifinder/app/engine/patterns/ (5 files) + synced to classifinder-engine/
- 21 true positive tests + 12 false positive tests + 1 boundary test in test_patterns.py (127 total tests, up from 93)
- 5 corpus files in classifinder-tests/corpus/known-secrets/ (103 tests pass)
- TP baseline regenerated
- Pattern count updated 50→71 across ~40+ files (site, SDK, MCP, docs, marketing, CLAUDE.md files)
- pattern-library.md updated with all 21 new entries (renumbered 1-71)
- patterns.astro catalog page updated

## Batch 2 Completion Log (2026-04-02)

**Result:** 71 → 82 patterns. All tests green (141 classifinder + 107 classifinder-tests).

**11 patterns added:**
- **ai.py** (+1): `deepseek_api_key` (sk- + deepseek context; dedup'd with OpenAI — detected as openai_api_key)
- **cloud.py** (+3): `vercel_access_token` (vca\_), `vercel_refresh_token` (vcr\_), `netlify_token` (nfp\_)
- **comms.py** (+5): `sentry_org_token` (sntrys\_eyJ), `sentry_user_token` (sntryu\_), `datadog_api_key` (32 hex + DD context), `datadog_app_key` (40 hex + DD context), `pagerduty_api_key` (u+ + PD context)
- **vcs.py** (+2): `airtable_api_key` (pat{14}.{64hex}), `nuget_api_key` (oy2)

**Deviations from plan:**
- Mistral AI — SKIPPED, no known prefix or format, too generic for reliable detection
- Together AI — SKIPPED, no prefix + "together" is a common English word, unacceptable FP rate
- Google AI/Gemini — SKIPPED, already covered by existing `gcp_api_key` (same AIza prefix)
- Vercel upgraded from context-dependent to prefix-anchored — new OAuth tokens use `vca_`/`vcr_` prefixes
- Netlify upgraded from context-dependent to prefix-anchored — new tokens use `nfp_` prefix
- Sentry upgraded from context-dependent to prefix-anchored — `sntrys_` and `sntryu_` prefixes confirmed
- Airtable upgraded from context-dependent to prefix-anchored — `pat{14}.{64hex}` is very distinctive
- Added DeepSeek dedup substitute mapping in classifinder-tests (openai_api_key wins over deepseek_api_key)
- Added `\x27` normalization fix to test regex comparator for PagerDuty pattern

**What was shipped:**
- Pattern code in classifinder/app/engine/patterns/ (4 files) + synced to classifinder-engine/
- 14 new tests in test_patterns.py (141 total, up from 127)
- 4 corpus files in classifinder-tests/corpus/known-secrets/
- Pattern count updated 71→82 across ~39 files
- pattern-library.md updated with all 11 new entries (renumbered 1-82)
- patterns.astro catalog page updated
- classifinder-tests dedup substitute map and regex normalizer updated

**Remaining (Batch 3):** Completed — see Batch 3 log below.

## Batch 3 Completion Log (2026-04-01)

**Result:** 82 → 88 patterns. All tests green (153 classifinder + 111 classifinder-tests).

**6 patterns added:**
- **cloud.py** (+1): `ibm_cloud_api_key` (44-char + IBM context)
- **comms.py** (+2): `figma_pat` (UUID-like + figma context), `auth0_management_token` (JWT + auth0 context)
- **database.py** (+1): `supabase_service_key` (HS256 JWT + supabase context)
- **payment.py** (+2): `ethereum_private_key` (0x + 64 hex + eth context), `bitcoin_wif_key` (Base58Check + btc context)

**Deviations from plan:**
- Railway token — SKIPPED, no official prefix format published, too generic for reliable detection
- Notion (#28 listed in Batch 3) — already done in Batch 1
- All 6 patterns are context-dependent (require provider keyword before the secret value)
- Ethereum Hardhat test key (`0xac09...`) added to `known_test_values` — confidence overrides to 0.15
- Auth0 and Supabase patterns set at 0.92 base confidence to win dedup over generic JWT (0.90)
- Ethereum and Bitcoin at 0.80 base with entropy_threshold=3.5

**What was shipped:**
- Pattern code in classifinder/app/engine/patterns/ (4 files) + synced to classifinder-engine/
- 12 new tests in test_patterns.py (153 total, up from 141): 6 TP + 6 FP tests
- 4 corpus files in classifinder-tests/corpus/known-secrets/
- Pattern count updated 82→88 across ~30 files
- pattern-library.md updated with all 6 new entries (renumbered 1-88)
- patterns.astro catalog page updated
- All 6 repos pushed

## Final Summary

| Batch | Patterns Added | Running Total | Date |
|-------|---------------|---------------|------|
| Start | — | 50 | — |
| Batch 1 | +21 (prefix-anchored) | 71 | 2026-04-01 |
| Batch 2 | +11 (context-dependent) | 82 | 2026-04-02 |
| Batch 3 | +6 (trickiest, highest FP risk) | 88 | 2026-04-01 |
| **Total** | **+38** | **88** | — |

**Skipped patterns (4):** Mistral AI (no prefix), Together AI (common word), Google AI/Gemini (covered by gcp_api_key), Railway (no prefix).

---

## Context

ClassiFinder currently has 50 detection patterns. The open-source `secrets-patterns-db` repo has 1,610 patterns across 1,421 providers. Most are low-quality raw regexes without confidence scoring, entropy analysis, or test value detection. However, there are 30-50 high-value patterns worth adding — especially providers that ClassiFinder's landing page already claims to detect but the engine doesn't actually implement.

**Goal:** Expand from 50 to ~80-90 patterns, prioritizing prefix-anchored patterns (lowest false-positive risk) and providers that matter to our target audience (AI/LLM developers, DevOps, platform engineers).

---

## Top 40 High-Value Patterns to Add

### Tier 1: AI/ML Providers (HIGH PRIORITY — our target audience)

These are critical because ClassiFinder positions itself as "built for AI pipelines" but only detects 3 AI providers. The landing page patterns.astro lists several of these already.

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Notes |
|---|-----------|----------|---------------|--------------------------|-------|
| 1 | `huggingface_token` | HuggingFace | `hf_[A-Za-z0-9]{34,}` | 0.97 | Distinctive prefix, very common in ML pipelines |
| 2 | `replicate_api_token` | Replicate | `r8_[A-Za-z0-9]{36,}` | 0.97 | Distinctive prefix |
| 3 | `google_ai_api_key` | Google AI (Gemini) | `AIzaSy[A-Za-z0-9_-]{33}` | 0.95 | Same format as GCP API key but used for Gemini — may overlap with existing gcp_api_key |
| 4 | `mistral_api_key` | Mistral AI | Context-dependent, no fixed prefix | 0.70 | Needs entropy + context keywords |
| 5 | `together_ai_api_key` | Together AI | Context-dependent | 0.70 | Needs entropy + context keywords |
| 6 | `groq_api_key` | Groq | `gsk_[A-Za-z0-9]{52,}` | 0.97 | Distinctive prefix |
| 7 | `deepseek_api_key` | DeepSeek | `sk-[a-f0-9]{32,}` | 0.75 | Overlaps with OpenAI sk- prefix, needs context keywords |

**Note:** Patterns 4, 5, 7 have no distinctive prefix — they'll need strong context_keywords (e.g., `["mistral", "MISTRAL_API_KEY"]`) and entropy thresholds to avoid false positives.

### Tier 2: DevOps & Infrastructure (HIGH PRIORITY — secondary audience)

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 8 | `doppler_token` | Doppler | `dp.pt.[A-Za-z0-9]{43}` | 0.97 | secrets-patterns-db (high confidence) |
| 9 | `terraform_cloud_token` | Terraform Cloud | `[A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}` | 0.97 | secrets-patterns-db (high confidence) |
| 10 | `vault_token` | HashiCorp Vault | `hvs\.[A-Za-z0-9]{24,}` | 0.97 | Not in secrets-patterns-db, but well-documented prefix |
| 11 | `vercel_token` | Vercel | Context-dependent, 24-char | 0.75 | secrets-patterns-db (needs context) |
| 12 | `netlify_token` | Netlify | Context-dependent, 43-45 char | 0.75 | secrets-patterns-db (needs context) |
| 13 | `railway_token` | Railway | Context-dependent | 0.70 | Not in secrets-patterns-db |
| 14 | `pulumi_access_token` | Pulumi | `pul-[a-f0-9]{40}` | 0.97 | Not in secrets-patterns-db, but documented prefix |
| 15 | `fly_api_token` | Fly.io | `fo1_[A-Za-z0-9]{39}` | 0.97 | Our own hosting provider! |

### Tier 3: Monitoring & Observability

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 16 | `datadog_api_key` | Datadog | 32-char hex, context-dependent | 0.75 | secrets-patterns-db (low confidence there) |
| 17 | `datadog_app_key` | Datadog | 40-char hex, context-dependent | 0.75 | secrets-patterns-db |
| 18 | `newrelic_admin_api_key` | New Relic | `NRAA-[a-f0-9]{27}` | 0.97 | secrets-patterns-db (high confidence) |
| 19 | `newrelic_insights_key` | New Relic | `NRI[IQ]-[A-Za-z0-9\-_]{32}` | 0.97 | secrets-patterns-db (high confidence) |
| 20 | `newrelic_rest_api_key` | New Relic | `NRRA-[a-f0-9]{42}` | 0.97 | secrets-patterns-db (high confidence) |
| 21 | `sentry_auth_token` | Sentry | `sntrys_[A-Za-z0-9]{48,}` (new format) or 64-char hex (old) | 0.95 | secrets-patterns-db has old format |
| 22 | `pagerduty_api_key` | PagerDuty | Structured format with `+` separator | 0.90 | secrets-patterns-db (high confidence) |
| 23 | `grafana_api_key` | Grafana | `glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}` (service account) | 0.97 | Not in secrets-patterns-db |

### Tier 4: SaaS & Productivity

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 24 | `linear_api_key` | Linear | `lin_api_[A-Za-z0-9]{40}` | 0.97 | secrets-patterns-db (high confidence) |
| 25 | `shopify_access_token` | Shopify | `shpat_[a-fA-F0-9]{32}` | 0.97 | secrets-patterns-db (high confidence) |
| 26 | `shopify_custom_token` | Shopify | `shpca_[a-fA-F0-9]{32}` | 0.97 | secrets-patterns-db |
| 27 | `shopify_private_token` | Shopify | `shppa_[a-fA-F0-9]{32}` | 0.97 | secrets-patterns-db |
| 28 | `notion_api_key` | Notion | `secret_[A-Za-z0-9]{43}` | 0.95 | secrets-patterns-db (high confidence) |
| 29 | `airtable_api_key` | Airtable | `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}` | 0.97 | Not in secrets-patterns-db, but documented |
| 30 | `figma_pat` | Figma | UUID-like with context | 0.80 | secrets-patterns-db |

### Tier 5: Package Registries & CI/CD

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 31 | `npm_token` | npm | `npm_[A-Za-z0-9]{36}` | 0.97 | Well-documented prefix |
| 32 | `pypi_token` | PyPI | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}` | 0.99 | secrets-patterns-db, very distinctive |
| 33 | `rubygems_token` | RubyGems | `rubygems_[A-Za-z0-9]{48}` | 0.97 | secrets-patterns-db |
| 34 | `nuget_api_key` | NuGet | `oy2[a-z0-9]{43}` | 0.90 | secrets-patterns-db |

### Tier 6: Auth Providers

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 35 | `auth0_management_token` | Auth0 | JWT with auth0 context | 0.85 | secrets-patterns-db |
| 36 | `supabase_service_key` | Supabase | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` prefix + supabase context | 0.85 | Not in secrets-patterns-db |

### Tier 7: Cloud Providers (Filling gaps)

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 37 | `alibaba_access_key` | Alibaba Cloud | `LTAI[A-Za-z0-9]{17,21}` | 0.95 | secrets-patterns-db (high confidence) |
| 38 | `ibm_cloud_api_key` | IBM Cloud | Context-dependent, 44-char | 0.75 | secrets-patterns-db |

### Tier 8: Crypto (Niche but high severity)

| # | Pattern ID | Provider | Prefix/Format | Suggested Base Confidence | Source |
|---|-----------|----------|---------------|--------------------------|--------|
| 39 | `ethereum_private_key` | Ethereum | `0x[a-fA-F0-9]{64}` with context | 0.80 | Not in secrets-patterns-db, well-known format |
| 40 | `bitcoin_wif_key` | Bitcoin | `[5KL][1-9A-HJ-NP-Za-km-z]{50,51}` (Base58Check) | 0.85 | Not in secrets-patterns-db |

---

## Implementation Priority

**Batch 1 (do first — prefix-anchored, lowest FP risk, ~20 patterns):**
Patterns 1, 2, 6, 8, 9, 10, 14, 15, 18, 19, 20, 23, 24, 25, 26, 27, 28, 31, 32, 33, 37

These all have distinctive prefixes → high base confidence, minimal tuning needed.

**Batch 2 (context-dependent, needs more care, ~12 patterns):**
Patterns 3, 4, 5, 7, 11, 12, 16, 17, 21, 22, 29, 34

These need entropy thresholds + context keywords to avoid false positives.

**Batch 3 (trickiest, most FP risk, ~8 patterns):**
Patterns 13, 30, 35, 36, 38, 39, 40, 28

These are context-heavy or format-ambiguous. Add last with careful corpus testing.

---

## Process: How to Add a New Pattern to ClassiFinder

Adding a pattern touches **4 repositories** and multiple files. Here's the complete checklist:

### Step 1: Define the Pattern (classifinder/app/engine/patterns/)

Choose the appropriate category file (or create a new one if needed):
- `cloud.py`, `payment.py`, `vcs.py`, `comms.py`, `database.py`, `ai.py`, `generic.py`

Add a `SecretPattern` instance with all required fields:

```python
MY_NEW_PATTERN = SecretPattern(
    id="provider_key_type",           # snake_case, unique
    name="Provider Key Type",          # Human-readable
    description="Description of the key format and how to recognize it",
    provider="provider",               # lowercase provider name
    severity="critical|high|medium|low",
    regex=re.compile(
        r"""prefix_(?P<secret>[A-Za-z0-9]{32,})""",  # MUST have (?P<secret>...) group
        re.VERBOSE,
    ),
    confidence_base=0.95,              # 0.95 for prefix-anchored, 0.60-0.80 for generic
    entropy_threshold=0.0,             # 0.0 to skip, 3.0-4.0 for generic patterns
    context_keywords=["provider", "PROVIDER_API_KEY", "provider_token"],
    known_test_values={"prefix_EXAMPLE123..."},  # Known docs/test values
    recommendation="Revoke at https://provider.com/settings and generate a new key.",
    tags=["category", "provider"],
)
```

Then register it at the bottom of the file:

```python
register(MY_NEW_PATTERN)  # or add to existing register() call
```

### Step 2: Sync to classifinder-engine/

Copy the exact same pattern definition to the corresponding file in `classifinder-engine/patterns/`. The pre-commit hook will block commits if the two engines diverge.

Files that must match:
- `classifinder/app/engine/scanner.py` ↔ `classifinder-engine/scanner.py`
- `classifinder/app/engine/redactor.py` ↔ `classifinder-engine/redactor.py`
- `classifinder/app/engine/entropy.py` ↔ `classifinder-engine/entropy.py`
- `classifinder/app/engine/patterns/*.py` ↔ `classifinder-engine/patterns/*.py`

### Step 3: Add Tests (classifinder/tests/)

In `tests/test_patterns.py`, add at minimum:
- A **true positive test** with a realistic example value
- A **test value detection test** if you defined known_test_values
- Optionally a **true negative test** for near-miss formats

Example:

```python
def test_provider_key_detected(self):
    """Provider key with valid prefix is detected."""
    text = "PROVIDER_API_KEY=prefix_abc123def456..."
    findings = scan(text)
    assert len(findings) == 1
    assert findings[0].type == "provider_key_type"
    assert findings[0].severity == "high"
    assert findings[0].confidence >= 0.90
```

### Step 4: Add Corpus Data (classifinder-tests/)

**Known-secrets corpus** — Add test cases to appropriate file in `classifinder-tests/corpus/known-secrets/`:
```
# expect: provider_key_type
# expect: provider_key_type >= 0.90
# description: Provider API key with standard prefix
PROVIDER_API_KEY=prefix_abc123def456ghi789...
```

If adding a new provider category, create a new corpus file.

**Benign corpus** — Check if existing benign files might false-positive on the new pattern. Run:
```bash
cd classifinder-tests && PYTHONPATH=. python -m pytest tests/test_benign.py -v
```

If new false positives appear, either:
- Tighten the regex
- Add entropy threshold
- Add to `lib/fp_allowlist.py` if the FP is acceptable at low confidence

### Step 5: Update TP Baseline (classifinder-tests/)

After adding corpus data, regenerate the true-positive baseline:
```bash
cd classifinder-tests && PYTHONPATH=. python reports/tp_report.py
```

Copy relevant new entries into `baselines/tp_baseline.json`.

### Step 6: Update Documentation

- **`classifinder/docs/pattern-library.md`** — Add the pattern with regex, example, description
- **`classifinder-marketing/docs/pattern-library.md`** — Keep in sync (or it may be the same file)
- **`classifinder-site/src/pages/patterns.astro`** — Add to the patterns catalog page
- **Update pattern count** everywhere it appears (currently "50"):
  - `classifinder-site/src/components/Demo.astro` (stats row)
  - `classifinder-site/src/components/Pricing.astro` (free tier)
  - `classifinder-site/src/components/HowItWorks.astro` (if mentioned)
  - `classifinder/docs/` various docs
  - `classifinder-sdk/README.md`
  - `classifinder-mcp/README.md`
  - Root `CLAUDE.md`

### Step 7: Run Full Test Suite

```bash
# API server tests (93 tests)
cd classifinder && python -m pytest tests/ -v

# Pattern quality tests
cd classifinder-tests && PYTHONPATH=. python -m pytest tests/ -v

# Parity check
cd classifinder-tests && PYTHONPATH=. python -m pytest tests/test_parity.py -v

# Engine sync check
cd classifinder-tests && bash scripts/check_engine_sync.sh
```

---

## Gap Analysis Instructions for Next Agent

To perform the detailed gap analysis:

1. **Read `classifinder-temp/secrets-patterns-db/db/rules-stable.yml`** — This is the main file with all 1,610 patterns. Each pattern has: pattern name, regex, confidence (high/low).

2. **Read ClassiFinder's existing patterns** — All in `classifinder/app/engine/patterns/` across 7 category files. There are exactly 50 patterns registered.

3. **Cross-reference** the Tier 1 patterns listed above against the actual regexes in rules-stable.yml. For prefix-anchored patterns, verify the prefix format against the provider's current documentation (prefixes change over time).

4. **For each pattern you implement:**
   - Find a real example from the provider's docs (for known_test_values)
   - Determine if the prefix is truly unique (no false positive risk)
   - Set appropriate entropy_threshold (0.0 for prefix patterns, 3.0+ for generic)
   - Write context_keywords from common env var names
   - Classify severity: critical (grants write access to production), high (grants read access or limited write), medium (test/sandbox keys), low (public or non-sensitive)

5. **Check the landing page claims** — `classifinder-site/src/pages/patterns.astro` lists patterns the site claims to detect. Cross-reference against what the engine actually implements. Any gap there is the highest priority to close.

---

## Reference: secrets-patterns-db File Locations

- Main patterns: `classifinder-temp/secrets-patterns-db/db/rules-stable.yml` (6,449 lines, 1,610 patterns)
- PII patterns: `classifinder-temp/secrets-patterns-db/db/pii-stable.yml` (144 patterns)
- Sensitive field names: `classifinder-temp/secrets-patterns-db/db/sensitive-fields-simple.yml` (529 fields)
- Conversion scripts: `classifinder-temp/secrets-patterns-db/scripts/convert-rules.py`

## Reference: ClassiFinder Pattern Files

- Registry: `classifinder/app/engine/patterns/registry.py` (SecretPattern dataclass + PATTERN_REGISTRY)
- Cloud (9): `classifinder/app/engine/patterns/cloud.py`
- Payment (8): `classifinder/app/engine/patterns/payment.py`
- VCS/CI (9): `classifinder/app/engine/patterns/vcs.py`
- Comms (9): `classifinder/app/engine/patterns/comms.py`
- Database (7): `classifinder/app/engine/patterns/database.py`
- AI (3): `classifinder/app/engine/patterns/ai.py`
- Generic (5): `classifinder/app/engine/patterns/generic.py`
