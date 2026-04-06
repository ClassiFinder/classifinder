"""
ClassiFinder — Pattern Test Case Registry

Data-driven test cases for every registered detection pattern.
Each entry defines positive samples (must detect), negative samples
(must not detect), and the expected minimum confidence.

Used by test_pattern_harness.py to auto-generate tests.

To add test cases for a new pattern, add an entry to PATTERN_TEST_CASES
with the pattern's ID as key. The harness will automatically generate
true positive, true negative, test value, and collision tests.
"""

# fmt: off

PATTERN_TEST_CASES: dict[str, dict] = {

    # ── AI / ML ──────────────────────────────────────────────────────────

    "openai_api_key": {
        "positives": [
            "OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz12345678",
            "sk-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "negatives": [
            "sk-short",
            "sk_live_notOpenAI1234567890abcdef",
        ],
        "min_confidence": 0.50,
    },

    "anthropic_api_key": {
        "positives": [
            "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
            'ANTHROPIC_API_KEY="sk-ant-admin01-zYxWvUtSrQpOnMlKjIhGfEdCbA"',
        ],
        "negatives": [
            "sk-ant-short",
            "sk-ant-unknown-prefix1234567890abcdef",
        ],
        "min_confidence": 0.90,
    },

    "cohere_api_key": {
        "positives": [
            "COHERE_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
            "cohere_key: ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210ZyXw",
        ],
        "negatives": [
            "random_value=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "min_confidence": 0.50,
    },

    "huggingface_token": {
        "positives": [
            "HF_TOKEN=hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678",
        ],
        "negatives": [
            "hf_short",
        ],
        "min_confidence": 0.90,
    },

    "replicate_api_token": {
        "positives": [
            "REPLICATE_API_TOKEN=r8_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
        ],
        "negatives": [
            "r8_short",
        ],
        "min_confidence": 0.90,
    },

    "groq_api_key": {
        "positives": [
            "GROQ_API_KEY=gsk_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQr",
        ],
        "negatives": [
            "gsk_short",
        ],
        "min_confidence": 0.90,
    },

    "deepseek_api_key": {
        "positives": [
            "DEEPSEEK_API_KEY=sk-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            'export DEEPSEEK_KEY="sk-abcdef0123456789abcdef0123456789"',
        ],
        "negatives": [
            "OPENAI_API_KEY=sk-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "sk-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        ],
        "min_confidence": 0.90,
    },

    "xai_api_key": {
        "positives": [
            "XAI_API_KEY=xai-AbCdEfGhIjKlMnOpQrStUv",
            'export XAI_KEY="xai-1234567890AbCdEfGhIjKl"',
        ],
        "negatives": [
            "xai-short",
            "The xai-protocol is used for communication",
        ],
        "min_confidence": 0.50,
    },

    "elevenlabs_api_key": {
        "positives": [
            "ELEVENLABS_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "xi-api-key: f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "min_confidence": 0.30,
    },

    "assemblyai_api_key": {
        "positives": [
            "ASSEMBLYAI_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "assemblyai_key = f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "min_confidence": 0.30,
    },

    "deepgram_api_key": {
        "positives": [
            "DEEPGRAM_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "deepgram_key = f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        ],
        "min_confidence": 0.30,
    },

    "langfuse_secret_key": {
        "positives": [
            "LANGFUSE_SECRET_KEY=sk-lf-AbCdEfGhIjKlMnOpQrStUv",
            'key = "sk-lf-1234567890-AbCdEfGhIjKl"',
        ],
        "negatives": [
            "sk-lf-short",
        ],
        "min_confidence": 0.50,
    },

    "mistral_api_key": {
        "positives": [
            "MISTRAL_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
            "mistral_key = Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4",
        ],
        "negatives": [
            "random_key = AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        ],
        "min_confidence": 0.30,
    },

    # ── Cloud / Infra ────────────────────────────────────────────────────

    "aws_access_key": {
        "positives": [
            "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284",
            "ASIAJEXAMPLEXEG2JICEA",
        ],
        "negatives": [
            "AKIAIOSFODNN7",
            "BKIAIOSFODNN7EXAMPLE12",
        ],
        "min_confidence": 0.10,  # test values get 0.15
    },

    "aws_secret_key": {
        "positives": [
            "AWS_SECRET_ACCESS_KEY=aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cA0fB3dE6gH9j",
        ],
        "negatives": [
            "random_value=aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cA0fB3dE6gH9j",
        ],
        "min_confidence": 0.50,
    },

    "gcp_api_key": {
        "positives": [
            "GOOGLE_API_KEY=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567",
        ],
        "negatives": [
            "AIza_too_short",
        ],
        "min_confidence": 0.50,
    },

    "azure_storage_key": {
        "positives": [
            "AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX==",
        ],
        "negatives": [
            "random_value=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX==",
        ],
        "min_confidence": 0.50,
    },

    "digitalocean_token": {
        "positives": [
            "DO_TOKEN=dop_v1_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        ],
        "negatives": [
            "dop_v1_short",
        ],
        "min_confidence": 0.90,
    },

    "cloudflare_api_token": {
        "positives": [
            "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz12345678901234",
        ],
        "negatives": [
            "random_value=AbCdEfGhIjKlMnOpQrStUvWxYz12345678901234",
        ],
        "min_confidence": 0.50,
    },

    "terraform_cloud_token": {
        "positives": [
            "AbCdEfGhIjKlMn.atlasv1.AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12345",
        ],
        "negatives": [
            "short.atlasv1.short",
        ],
        "min_confidence": 0.90,
    },

    "vault_token": {
        "positives": [
            "VAULT_TOKEN=hvs.AbCdEfGhIjKlMnOpQrStUvWx",
        ],
        "negatives": [
            "hvs.short",
        ],
        "min_confidence": 0.90,
    },

    "doppler_token": {
        "positives": [
            "DOPPLER_TOKEN=dp.pt.AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "negatives": [
            "dp.pt.short",
        ],
        "min_confidence": 0.90,
    },

    "pulumi_access_token": {
        "positives": [
            "PULUMI_ACCESS_TOKEN=pul-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        ],
        "negatives": [
            "pul-short",
        ],
        "min_confidence": 0.90,
    },

    "fly_api_token": {
        "positives": [
            "FLY_API_TOKEN=fo1_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        ],
        "negatives": [
            "fo1_short",
        ],
        "min_confidence": 0.90,
    },

    "alibaba_access_key": {
        "positives": [
            "ALIBABA_KEY=LTAIAbCdEfGhIjKlMnOpQr",
        ],
        "negatives": [
            "LTAIshort",
        ],
        "min_confidence": 0.90,
    },

    "vercel_access_token": {
        "positives": [
            "VERCEL_TOKEN=vca_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOp",
        ],
        "negatives": [
            "vca_short",
        ],
        "min_confidence": 0.90,
    },

    "netlify_token": {
        "positives": [
            "NETLIFY_AUTH_TOKEN=nfp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
        ],
        "negatives": [
            "nfp_short",
        ],
        "min_confidence": 0.90,
    },

    "okta_api_token": {
        "positives": [
            "OKTA_API_TOKEN=00AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "negatives": [
            "random_value=00AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "min_confidence": 0.50,
    },

    "buildkite_token": {
        "positives": [
            "BUILDKITE_TOKEN=bkua_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "negatives": [
            "bkub_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "min_confidence": 0.90,
    },

    "railway_token": {
        "positives": [
            "RAILWAY_TOKEN=a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        ],
        "negatives": [
            "random_value=a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        ],
        "min_confidence": 0.50,
    },

    # ── VCS / CI / Package Registries ────────────────────────────────────

    "github_pat_classic": {
        "positives": [
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu",
        ],
        "negatives": [
            "ghp_short",
        ],
        "min_confidence": 0.90,
    },

    "github_pat_fine_grained": {
        "positives": [
            "GITHUB_TOKEN=github_pat_" + "A" * 82,
        ],
        "negatives": [
            "github_pat_tooshort",
        ],
        "min_confidence": 0.90,
    },

    "github_oauth_secret": {
        "positives": [
            "CLIENT_SECRET=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        ],
        "negatives": [
            "gho_short",
        ],
        "min_confidence": 0.90,
    },

    "gitlab_pat": {
        "positives": [
            "GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRST",
        ],
        "negatives": [
            "glpat-short",
        ],
        "min_confidence": 0.90,
    },

    "circleci_token": {
        "positives": [
            "CIRCLECI_TOKEN=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        ],
        "min_confidence": 0.50,
    },

    "npm_token": {
        "positives": [
            "NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
        ],
        "negatives": [
            "npm_short",
        ],
        "min_confidence": 0.90,
    },

    "pypi_token": {
        "positives": [
            "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcAbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz",
        ],
        "negatives": [
            "pypi-wrongprefix1234567890",
        ],
        "min_confidence": 0.90,
    },

    "rubygems_token": {
        "positives": [
            "GEM_HOST_API_KEY=rubygems_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKl",
        ],
        "negatives": [
            "rubygems_short",
        ],
        "min_confidence": 0.90,
    },

    "nuget_api_key": {
        "positives": [
            "NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz1234567890abcdefg",
        ],
        "negatives": [
            "oy2short",
        ],
        "min_confidence": 0.50,
    },

    "airtable_api_key": {
        "positives": [
            "AIRTABLE_KEY=patAbCdEfGhIjKlMn.a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        ],
        "negatives": [
            "patAbCdEfGhIjKlMn_no_dot_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "min_confidence": 0.50,
    },

    # ── Communication / SaaS ─────────────────────────────────────────────

    "slack_bot_token": {
        "positives": [
            "SLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx",
        ],
        "negatives": [
            "xoxb-short",
        ],
        "min_confidence": 0.90,
    },

    "slack_webhook_url": {
        "positives": [
            "https://hooks.slack.com/services/T01234567/B01234567AB/abcdefghijklmnopqrstuvwx",
        ],
        "negatives": [
            "https://hooks.slack.com/services/T0123/short",
        ],
        "min_confidence": 0.90,
    },

    "sendgrid_api_key": {
        "positives": [
            "SG.ABCDEFGHIJKLMNOPQRSTuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
        ],
        "negatives": [
            "SG.short.short",
        ],
        "min_confidence": 0.90,
    },

    "mailgun_api_key": {
        "positives": [
            "MAILGUN_API_KEY=key-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "negatives": [
            "key-short",
        ],
        "min_confidence": 0.90,
    },

    "discord_bot_token": {
        "positives": [
            "DISCORD_TOKEN=MTIzNDU2Nzg5MDEyMzQ1Njc4.GhIjKl.MnOpQrStUvWxYz1234567890AbCdEfGhIj",
        ],
        "negatives": [
            "not.a.token",
        ],
        "min_confidence": 0.50,
    },

    "discord_webhook_url": {
        "positives": [
            "https://discord.com/api/webhooks/12345678901234567/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12",
        ],
        "negatives": [
            "https://discord.com/api/webhooks/123/short",
        ],
        "min_confidence": 0.90,
    },

    "telegram_bot_token": {
        "positives": [
            "TELEGRAM_TOKEN=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
        ],
        "negatives": [
            "123:short",
        ],
        "min_confidence": 0.50,
    },

    "teams_webhook_url": {
        "positives": [
            "https://myorg.webhook.office.com/webhookb2/a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6@f1e2d3c4-b5a6-f7e8-d9c0-b1a2f3e4d5c6/IncomingWebhook/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/f1e2d3c4-b5a6-f7e8-d9c0-b1a2f3e4d5c6",
        ],
        "negatives": [
            "https://example.webhook.office.com/short",
        ],
        "min_confidence": 0.90,
    },

    "mattermost_token": {
        "positives": [
            "MATTERMOST_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6g7h8i9j0k1l2m3",
        ],
        "min_confidence": 0.30,
    },

    "linear_api_key": {
        "positives": [
            "LINEAR_API_KEY=lin_api_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
        ],
        "negatives": [
            "lin_api_short",
        ],
        "min_confidence": 0.90,
    },

    "notion_api_key": {
        "positives": [
            "NOTION_TOKEN=secret_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
        ],
        "negatives": [
            "secret_short",
        ],
        "min_confidence": 0.90,
    },

    "sentry_org_token": {
        "positives": [
            "SENTRY_AUTH_TOKEN=sntrys_eyJhbGciOiJIUzI1NiJ9" + "A" * 80,
        ],
        "negatives": [
            "sntrys_short",
        ],
        "min_confidence": 0.90,
    },

    "datadog_api_key": {
        "positives": [
            "DD_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "negatives": [
            "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
        "min_confidence": 0.50,
    },

    "grafana_api_key": {
        "positives": [
            "GRAFANA_API_KEY=glsa_AbCdEfGhIjKlMnOpQrStUvWxYz123456_a1b2c3d4",
        ],
        "negatives": [
            "glsa_short_a1b2c3d4",
        ],
        "min_confidence": 0.90,
    },

    "auth0_management_token": {
        "positives": [
            "AUTH0_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
        "negatives": [
            "random_jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
        ],
        "min_confidence": 0.50,
    },

    "figma_pat": {
        "positives": [
            "FIGMA_TOKEN=12345-a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        ],
        "negatives": [
            "random_value=12345-a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        ],
        "min_confidence": 0.50,
    },

    # ── Payment ──────────────────────────────────────────────────────────

    "stripe_live_secret_key": {
        "positives": [
            "STRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd",
        ],
        "negatives": [
            "sk_live_short",
        ],
        "min_confidence": 0.90,
    },

    "stripe_test_secret_key": {
        "positives": [
            "sk_test_51H3aKLkdsjfhDKJSH38djfhksd",
        ],
        "negatives": [
            "sk_test_short",
        ],
        "min_confidence": 0.10,  # test values get 0.15
    },

    "stripe_webhook_secret": {
        "positives": [
            "WEBHOOK_SECRET=whsec_1234abcd5678efgh9012ijkl",
        ],
        "negatives": [
            "whsec_short",
        ],
        "min_confidence": 0.90,
    },

    "shopify_access_token": {
        "positives": [
            "SHOPIFY_TOKEN=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",
        ],
        "negatives": [
            "shpat_short",
        ],
        "min_confidence": 0.90,
    },

    "razorpay_key": {
        "positives": [
            "RAZORPAY_KEY=rzp_live_AbCdEfGhIjKlMn",
            "rzp_test_ZyXwVuTsRqPoNm",
        ],
        "negatives": [
            "rzp_dev_AbCdEfGhIjKlMn",
        ],
        "min_confidence": 0.50,
    },

    # ── Database / Infra ─────────────────────────────────────────────────

    "postgres_connection_string": {
        "positives": [
            "DATABASE_URL=postgres://myuser:s3cretP4ss@db.example.com:5432/prod",
        ],
        "negatives": [
            "postgres://localhost/mydb",  # no password
        ],
        "min_confidence": 0.10,  # test values get low confidence
    },

    "mongodb_connection_string": {
        "positives": [
            "MONGO_URL=mongodb+srv://admin:s3cretP4ss@cluster0.example.mongodb.net/prod",
        ],
        "negatives": [
            "mongodb://localhost/mydb",  # no password
        ],
        "min_confidence": 0.10,
    },

    "ssh_private_key": {
        "positives": [
            "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 60 + "\n" * 5 + "-----END RSA PRIVATE KEY-----",
        ],
        "negatives": [
            "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----",
        ],
        "min_confidence": 0.90,
    },

    "supabase_service_key": {
        "positives": [
            "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjI1NjE0NDAwfQ.AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEf",
        ],
        "negatives": [
            "random_jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        ],
        "min_confidence": 0.50,
    },

    # ── Generic ──────────────────────────────────────────────────────────

    "jwt_token": {
        "positives": [
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.AbCdEfGhIjKlMnOpQrStUvWxYz",
        ],
        "negatives": [
            "eyJ.short.sig",
        ],
        "min_confidence": 0.50,
    },

    "generic_api_key_env": {
        "positives": [
            "API_KEY=zB3kE6gH9jK2mN5pQ8sT",
        ],
        "negatives": [
            "API_KEY=short",
        ],
        "min_confidence": 0.10,
    },
}

# fmt: on
