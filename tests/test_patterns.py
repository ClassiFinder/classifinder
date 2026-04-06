"""
SecretSweep — Pattern Test Suite

Tests every registered pattern against known true positives, true negatives,
and edge cases. Run with: python -m pytest tests/test_patterns.py -v

Each test case validates:
- True positives: text that SHOULD trigger the pattern
- True negatives: similar-looking text that should NOT trigger
- That confidence scores are within expected ranges
- That known test values are correctly flagged
"""

import sys
import os

import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine.scanner import scan


# ═══════════════════════════════════════════════
# AWS
# ═══════════════════════════════════════════════

def test_aws_access_key_true_positives():
    """Real-format AWS access keys should be detected."""
    cases = [
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "key: AKIAI44QH8DHBEXAMPLE",
        'export AWS_ACCESS_KEY_ID="AKIAJGKJHSKLDJFH3284"',
        "ASIAJEXAMPLEXEG2JICEA",  # STS temporary key
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)  # low threshold to catch test values too
        aws_findings = [f for f in findings if f.type == "aws_access_key"]
        assert len(aws_findings) >= 1, f"Failed to detect AWS key in: {text}"


def test_aws_access_key_true_negatives():
    """Strings that look similar but aren't AWS keys should not trigger."""
    cases = [
        "AKIAIOSFODNN7",           # too short (13 chars after prefix)
        "BKIAIOSFODNN7EXAMPLE12",  # wrong prefix
        "The AKIA protocol is used for authentication",  # AKIA as word, not key
        "AKIA followed by lowercase akiaiosfodnn7example",  # lowercase
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.3)
        aws_findings = [f for f in findings if f.type == "aws_access_key"]
        assert len(aws_findings) == 0, f"False positive on: {text}"


def test_aws_access_key_test_value_flagged():
    """Known AWS example keys should be detected but flagged as test values."""
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.1)
    aws_findings = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws_findings) == 1
    assert aws_findings[0].is_likely_test_value is True
    assert aws_findings[0].confidence < 0.3


# ═══════════════════════════════════════════════
# STRIPE
# ═══════════════════════════════════════════════

def test_stripe_live_key_detected():
    """Stripe live secret keys should be detected with high confidence."""
    text = 'STRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd'
    findings = scan(text)
    stripe_findings = [f for f in findings if f.type == "stripe_live_secret_key"]
    assert len(stripe_findings) == 1
    assert stripe_findings[0].confidence >= 0.95
    assert stripe_findings[0].severity == "critical"


def test_stripe_test_key_lower_severity():
    """Stripe test keys should be detected but with medium severity."""
    text = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
    findings = scan(text, min_confidence=0.1)
    stripe_findings = [f for f in findings if f.type == "stripe_test_secret_key"]
    assert len(stripe_findings) == 1
    assert stripe_findings[0].severity == "medium"


def test_stripe_webhook_secret():
    text = "WEBHOOK_SECRET=whsec_1234abcd5678efgh9012ijkl"
    findings = scan(text)
    wh_findings = [f for f in findings if f.type == "stripe_webhook_secret"]
    assert len(wh_findings) == 1


# ═══════════════════════════════════════════════
# GITHUB
# ═══════════════════════════════════════════════

def test_github_classic_pat():
    text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    findings = scan(text)
    gh_findings = [f for f in findings if f.type == "github_pat_classic"]
    assert len(gh_findings) == 1
    assert gh_findings[0].confidence >= 0.95


def test_github_fine_grained_pat():
    token = "github_pat_" + "A" * 82
    text = f"TOKEN={token}"
    findings = scan(text)
    gh_findings = [f for f in findings if f.type == "github_pat_fine_grained"]
    assert len(gh_findings) == 1


def test_gitlab_pat():
    text = "GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRST"
    findings = scan(text)
    gl_findings = [f for f in findings if f.type == "gitlab_pat"]
    assert len(gl_findings) == 1


# ═══════════════════════════════════════════════
# SLACK
# ═══════════════════════════════════════════════

def test_slack_bot_token():
    text = "SLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx"
    findings = scan(text)
    slack_findings = [f for f in findings if f.type == "slack_bot_token"]
    assert len(slack_findings) == 1


def test_slack_webhook():
    text = "https://hooks.slack.com/services/T01234567/B01234567AB/abcdefghijklmnopqrstuvwx"
    findings = scan(text)
    wh_findings = [f for f in findings if f.type == "slack_webhook_url"]
    assert len(wh_findings) == 1


# ═══════════════════════════════════════════════
# SENDGRID
# ═══════════════════════════════════════════════

def test_sendgrid_api_key():
    text = "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs"
    findings = scan(text)
    sg_findings = [f for f in findings if f.type == "sendgrid_api_key"]
    assert len(sg_findings) == 1
    assert sg_findings[0].confidence >= 0.95


# ═══════════════════════════════════════════════
# DATABASE CONNECTION STRINGS
# ═══════════════════════════════════════════════

def test_postgres_connection_string():
    text = "DATABASE_URL=postgres://admin:s3cur3p4ss@db.internal:5432/production"
    findings = scan(text)
    pg_findings = [f for f in findings if f.type == "postgres_connection_string"]
    assert len(pg_findings) == 1


def test_mongodb_connection_string():
    text = 'MONGO_URL="mongodb+srv://user:MyP4ssword@cluster0.abc123.mongodb.net/mydb"'
    findings = scan(text)
    mongo_findings = [f for f in findings if f.type == "mongodb_connection_string"]
    assert len(mongo_findings) == 1


# ═══════════════════════════════════════════════
# PRIVATE KEYS
# ═══════════════════════════════════════════════

def test_rsa_private_key():
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PdFsHEIhEOGP8yrFkGa1GwUyj
k2e4J1J5LskqG2Kv2VjGFHjK5JFqT9E3lZRv/7Kbh4L9LPvX5lKxq7rG5V3R9Dl
xGJiZm7H1p8Z6w/mXwGE2j9xDQ5L3RfqfG5JdBfl9F3Pt9C3bT0G3Jj+1F0tR5y
ZC4GhX8jM7zN7Z5Ae3f0f6n0t7L2K5Kj3Y8xRG1B2R4Gd0f2j5K6v3N7Y2x8L9
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop
-----END RSA PRIVATE KEY-----"""
    findings = scan(text)
    key_findings = [f for f in findings if f.type == "ssh_private_key"]
    assert len(key_findings) == 1
    assert key_findings[0].severity == "critical"


# ═══════════════════════════════════════════════
# JWT
# ═══════════════════════════════════════════════

def test_jwt_token_standalone():
    """JWT without Bearer context should be detected as jwt_token."""
    # Use a JWT that is NOT in the known_test_values set
    text = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.XYZ123abc456def789ghi012jkl345mno678pqr"
    findings = scan(text, min_confidence=0.1)
    jwt_findings = [f for f in findings if f.type == "jwt_token"]
    assert len(jwt_findings) >= 1, f"Expected jwt_token, got: {[f.type for f in findings]}"


def test_jwt_in_bearer_header():
    """JWT inside a Bearer header should be detected (as either jwt or bearer)."""
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = scan(text, min_confidence=0.1)
    relevant = [f for f in findings if f.type in ("jwt_token", "bearer_token")]
    assert len(relevant) >= 1, f"Expected jwt or bearer finding, got: {[f.type for f in findings]}"


# ═══════════════════════════════════════════════
# OPENAI
# ═══════════════════════════════════════════════

def test_openai_api_key():
    """OpenAI API keys with sk- prefix should be detected."""
    text = "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
    findings = scan(text)
    openai_findings = [f for f in findings if f.type == "openai_api_key"]
    assert len(openai_findings) == 1
    assert openai_findings[0].severity == "critical"


def test_openai_project_key():
    """OpenAI project-scoped keys with sk-proj- prefix should be detected."""
    text = "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
    findings = scan(text)
    openai_findings = [f for f in findings if f.type == "openai_api_key"]
    assert len(openai_findings) == 1


# ═══════════════════════════════════════════════
# ANTHROPIC
# ═══════════════════════════════════════════════

def test_anthropic_api_key():
    """Anthropic API keys with sk-ant- prefix should be detected."""
    text = "ANTHROPIC_API_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901"
    findings = scan(text)
    ant_findings = [f for f in findings if f.type == "anthropic_api_key"]
    assert len(ant_findings) == 1
    assert ant_findings[0].severity == "critical"
    assert ant_findings[0].confidence >= 0.95


# ═══════════════════════════════════════════════
# COHERE
# ═══════════════════════════════════════════════

def test_cohere_api_key():
    """Cohere API keys with context should be detected."""
    text = "COHERE_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    findings = scan(text)
    cohere_findings = [f for f in findings if f.type == "cohere_api_key"]
    assert len(cohere_findings) == 1
    assert cohere_findings[0].severity == "high"


# ═══════════════════════════════════════════════
# CREDIT CARDS
# ═══════════════════════════════════════════════

def test_credit_card_visa_luhn_valid():
    """A Luhn-valid Visa number should be detected."""
    text = "card_number=4532015112830366"
    findings = scan(text)
    cc_findings = [f for f in findings if f.type == "credit_card_number"]
    assert len(cc_findings) == 1
    assert cc_findings[0].severity == "high"
    assert cc_findings[0].confidence >= 0.5


def test_credit_card_luhn_invalid():
    """A Luhn-invalid number should not be detected (confidence drops below threshold)."""
    text = "card_number=4532015112830367"  # last digit changed, fails Luhn
    findings = scan(text)
    cc_findings = [f for f in findings if f.type == "credit_card_number"]
    assert len(cc_findings) == 0


def test_credit_card_test_value():
    """Known test card numbers should be flagged as test values."""
    text = "card=4111111111111111"
    findings = scan(text, min_confidence=0.1)
    cc_findings = [f for f in findings if f.type == "credit_card_number"]
    assert len(cc_findings) == 1
    assert cc_findings[0].is_likely_test_value is True


def test_credit_card_with_dashes():
    """Card numbers with dashes should be detected."""
    text = "card=4532-0151-1283-0366"
    findings = scan(text)
    cc_findings = [f for f in findings if f.type == "credit_card_number"]
    assert len(cc_findings) == 1


def test_credit_card_amex():
    """Amex numbers (15 digits, starts with 34/37) should be detected."""
    text = "card=378282246310005"  # Luhn-valid Amex
    findings = scan(text)
    cc_findings = [f for f in findings if f.type == "credit_card_number"]
    assert len(cc_findings) == 1


# ═══════════════════════════════════════════════
# HUGGINGFACE
# ═══════════════════════════════════════════════

def test_huggingface_token():
    """HuggingFace tokens with hf_ prefix should be detected."""
    text = "HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    findings = scan(text)
    hf_findings = [f for f in findings if f.type == "huggingface_token"]
    assert len(hf_findings) == 1
    assert hf_findings[0].confidence >= 0.95


# ═══════════════════════════════════════════════
# REPLICATE
# ═══════════════════════════════════════════════

def test_replicate_api_token():
    """Replicate tokens with r8_ prefix should be detected."""
    text = "REPLICATE_API_TOKEN=r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    findings = scan(text)
    rep_findings = [f for f in findings if f.type == "replicate_api_token"]
    assert len(rep_findings) == 1
    assert rep_findings[0].confidence >= 0.95


# ═══════════════════════════════════════════════
# GROQ
# ═══════════════════════════════════════════════

def test_groq_api_key():
    """Groq API keys with gsk_ prefix should be detected."""
    text = "GROQ_API_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    findings = scan(text)
    groq_findings = [f for f in findings if f.type == "groq_api_key"]
    assert len(groq_findings) == 1
    assert groq_findings[0].severity == "critical"


# ═══════════════════════════════════════════════
# DOPPLER
# ═══════════════════════════════════════════════

def test_doppler_token():
    """Doppler tokens with dp.pt. prefix should be detected (40-44 char range)."""
    # 43 chars (most common observed length)
    text = "DOPPLER_TOKEN=dp.pt.ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef"
    findings = scan(text)
    dp_findings = [f for f in findings if f.type == "doppler_token"]
    assert len(dp_findings) == 1
    assert dp_findings[0].confidence >= 0.95


def test_doppler_token_length_boundaries():
    """Doppler tokens at 40 and 44 chars should match; 39 should not."""
    # 40 chars (minimum per Doppler spec)
    text_40 = "dp.pt." + "A" * 40
    assert len([f for f in scan(text_40) if f.type == "doppler_token"]) == 1
    # 44 chars (maximum per Doppler spec)
    text_44 = "dp.pt." + "A" * 44
    assert len([f for f in scan(text_44) if f.type == "doppler_token"]) == 1
    # 39 chars (too short)
    text_39 = "dp.pt." + "A" * 39
    assert len([f for f in scan(text_39) if f.type == "doppler_token"]) == 0


# ═══════════════════════════════════════════════
# TERRAFORM CLOUD
# ═══════════════════════════════════════════════

def test_terraform_cloud_token():
    """Terraform Cloud tokens with .atlasv1. segment should be detected."""
    text = "TF_TOKEN=ABCDEFGHIJKLmn.atlasv1.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDE"
    findings = scan(text)
    tf_findings = [f for f in findings if f.type == "terraform_cloud_token"]
    assert len(tf_findings) == 1
    assert tf_findings[0].severity == "critical"


# ═══════════════════════════════════════════════
# HASHICORP VAULT
# ═══════════════════════════════════════════════

def test_vault_token():
    """Vault tokens with hvs. prefix should be detected."""
    text = "VAULT_TOKEN=hvs.ABCDEFGHIJKLMNOPQRSTUVwx"
    findings = scan(text)
    vault_findings = [f for f in findings if f.type == "vault_token"]
    assert len(vault_findings) == 1
    assert vault_findings[0].confidence >= 0.95


# ═══════════════════════════════════════════════
# PULUMI
# ═══════════════════════════════════════════════

def test_pulumi_access_token():
    """Pulumi tokens with pul- prefix should be detected."""
    text = "PULUMI_ACCESS_TOKEN=pul-abcdef0123456789abcdef0123456789abcdef01"
    findings = scan(text)
    pul_findings = [f for f in findings if f.type == "pulumi_access_token"]
    assert len(pul_findings) == 1


# ═══════════════════════════════════════════════
# FLY.IO
# ═══════════════════════════════════════════════

def test_fly_api_token():
    """Fly.io tokens with fo1_ prefix should be detected."""
    text = "FLY_API_TOKEN=fo1_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
    findings = scan(text)
    fly_findings = [f for f in findings if f.type == "fly_api_token"]
    assert len(fly_findings) == 1
    assert fly_findings[0].severity == "critical"


# ═══════════════════════════════════════════════
# ALIBABA CLOUD
# ═══════════════════════════════════════════════

def test_alibaba_access_key():
    """Alibaba Cloud keys with LTAI prefix should be detected."""
    text = "ALIBABA_ACCESS_KEY=LTAIabcdefghijklmnopq"
    findings = scan(text)
    ali_findings = [f for f in findings if f.type == "alibaba_access_key"]
    assert len(ali_findings) == 1


# ═══════════════════════════════════════════════
# NEW RELIC
# ═══════════════════════════════════════════════

def test_newrelic_admin_api_key():
    """New Relic admin keys with NRAA- prefix should be detected."""
    text = "NEW_RELIC_API_KEY=NRAA-abcdef0123456789abcdef01234"
    findings = scan(text)
    nr_findings = [f for f in findings if f.type == "newrelic_admin_api_key"]
    assert len(nr_findings) == 1


def test_newrelic_insights_key():
    """New Relic Insights keys with NRII/NRIQ prefix should be detected."""
    text = "NEW_RELIC_INSERT_KEY=NRII-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    findings = scan(text)
    nr_findings = [f for f in findings if f.type == "newrelic_insights_key"]
    assert len(nr_findings) == 1


def test_newrelic_user_api_key():
    """New Relic user API keys with NRAK- prefix should be detected."""
    text = "NEW_RELIC_API_KEY=NRAK-abc0123456789def0123456789a"
    findings = scan(text)
    nr_findings = [f for f in findings if f.type == "newrelic_user_api_key"]
    assert len(nr_findings) == 1


# ═══════════════════════════════════════════════
# GRAFANA
# ═══════════════════════════════════════════════

def test_grafana_api_key():
    """Grafana service account tokens with glsa_ prefix should be detected."""
    text = "GRAFANA_API_KEY=glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_abcdef01"
    findings = scan(text)
    gf_findings = [f for f in findings if f.type == "grafana_api_key"]
    assert len(gf_findings) == 1


# ═══════════════════════════════════════════════
# LINEAR
# ═══════════════════════════════════════════════

def test_linear_api_key():
    """Linear API keys with lin_api_ prefix should be detected."""
    text = "LINEAR_API_KEY=lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
    findings = scan(text)
    lin_findings = [f for f in findings if f.type == "linear_api_key"]
    assert len(lin_findings) == 1


# ═══════════════════════════════════════════════
# NOTION
# ═══════════════════════════════════════════════

def test_notion_api_key():
    """Notion integration tokens with secret_ prefix should be detected."""
    text = "NOTION_API_KEY=secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef"
    findings = scan(text)
    notion_findings = [f for f in findings if f.type == "notion_api_key"]
    assert len(notion_findings) == 1


# ═══════════════════════════════════════════════
# SHOPIFY
# ═══════════════════════════════════════════════

def test_shopify_access_token():
    """Shopify access tokens with shpat_ prefix should be detected."""
    text = "SHOPIFY_ACCESS_TOKEN=shpat_abcdef0123456789abcdef0123456789"
    findings = scan(text)
    sh_findings = [f for f in findings if f.type == "shopify_access_token"]
    assert len(sh_findings) == 1
    assert sh_findings[0].severity == "critical"


def test_shopify_custom_token():
    """Shopify custom app tokens with shpca_ prefix should be detected."""
    text = "SHOPIFY_TOKEN=shpca_abcdef0123456789abcdef0123456789"
    findings = scan(text)
    sh_findings = [f for f in findings if f.type == "shopify_custom_token"]
    assert len(sh_findings) == 1


def test_shopify_private_token():
    """Shopify private app tokens with shppa_ prefix should be detected."""
    text = "SHOPIFY_PRIVATE=shppa_abcdef0123456789abcdef0123456789"
    findings = scan(text)
    sh_findings = [f for f in findings if f.type == "shopify_private_token"]
    assert len(sh_findings) == 1


# ═══════════════════════════════════════════════
# NPM
# ═══════════════════════════════════════════════

def test_npm_token():
    """npm tokens with npm_ prefix should be detected."""
    text = "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    findings = scan(text)
    npm_findings = [f for f in findings if f.type == "npm_token"]
    assert len(npm_findings) == 1
    assert npm_findings[0].severity == "critical"


# ═══════════════════════════════════════════════
# PYPI
# ═══════════════════════════════════════════════

def test_pypi_token():
    """PyPI tokens with pypi-AgEIcHlwaS5vcmc prefix should be detected."""
    text = "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcCJGI4ZjE3YjFkLTk1NDMtNGRiMS1hYjFhLThlOTIxMTk3N2YzNgACKlszLCJhMTRiNjcx"
    findings = scan(text)
    pypi_findings = [f for f in findings if f.type == "pypi_token"]
    assert len(pypi_findings) == 1
    assert pypi_findings[0].confidence >= 0.97


# ═══════════════════════════════════════════════
# RUBYGEMS
# ═══════════════════════════════════════════════

def test_rubygems_token():
    """RubyGems tokens with rubygems_ prefix should be detected."""
    text = "GEM_HOST_API_KEY=rubygems_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
    findings = scan(text)
    rg_findings = [f for f in findings if f.type == "rubygems_token"]
    assert len(rg_findings) == 1


# ═══════════════════════════════════════════════
# BATCH 2: DEEPSEEK
# ═══════════════════════════════════════════════

def test_deepseek_api_key():
    """DeepSeek API keys with DeepSeek context are correctly typed as deepseek_api_key.

    DeepSeek uses sk-{32hex} which overlaps with OpenAI's sk-{32,} pattern.
    When DeepSeek context is present, the DeepSeek pattern wins dedup with
    higher confidence (0.92 base + context boost > OpenAI's 0.90 base).
    """
    text = "DEEPSEEK_API_KEY=sk-abcdef0123456789abcdef0123456789"
    findings = scan(text)
    sk_findings = [f for f in findings if f.type == "deepseek_api_key"]
    assert len(sk_findings) == 1
    assert sk_findings[0].confidence >= 0.92


# ═══════════════════════════════════════════════
# BATCH 2: VERCEL
# ═══════════════════════════════════════════════

def test_vercel_access_token():
    """Vercel access tokens with vca_ prefix should be detected."""
    text = "VERCEL_TOKEN=vca_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01"
    findings = scan(text)
    vc_findings = [f for f in findings if f.type == "vercel_access_token"]
    assert len(vc_findings) == 1
    assert vc_findings[0].confidence >= 0.93


def test_vercel_refresh_token():
    """Vercel refresh tokens with vcr_ prefix should be detected."""
    text = "VERCEL_REFRESH=vcr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01"
    findings = scan(text)
    vc_findings = [f for f in findings if f.type == "vercel_refresh_token"]
    assert len(vc_findings) == 1


# ═══════════════════════════════════════════════
# BATCH 2: NETLIFY
# ═══════════════════════════════════════════════

def test_netlify_token():
    """Netlify tokens with nfp_ prefix should be detected."""
    text = "NETLIFY_AUTH_TOKEN=nfp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    findings = scan(text)
    nf_findings = [f for f in findings if f.type == "netlify_token"]
    assert len(nf_findings) == 1


# ═══════════════════════════════════════════════
# BATCH 2: SENTRY
# ═══════════════════════════════════════════════

def test_sentry_org_token():
    """Sentry org tokens with sntrys_eyJ prefix should be detected."""
    text = "SENTRY_AUTH_TOKEN=sntrys_eyJpYXQiOiIxNjk5MDAwMDAwIiwiaXNzIjoic2VudHJ5Iiwib3JnIjoic2x1ZyIsInNjb3BlcyI6WyJvcmc6cmVhZCJdfQ_ABCDEFGHIJklmnopqrstu"
    findings = scan(text)
    sn_findings = [f for f in findings if f.type == "sentry_org_token"]
    assert len(sn_findings) == 1
    assert sn_findings[0].severity == "critical"


def test_sentry_user_token():
    """Sentry user tokens with sntryu_ prefix should be detected."""
    text = "SENTRY_AUTH_TOKEN=sntryu_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    findings = scan(text)
    sn_findings = [f for f in findings if f.type == "sentry_user_token"]
    assert len(sn_findings) == 1


# ═══════════════════════════════════════════════
# BATCH 2: DATADOG
# ═══════════════════════════════════════════════

def test_datadog_api_key():
    """Datadog API keys with DD context should be detected."""
    text = "DD_API_KEY=abcdef0123456789abcdef0123456789"
    findings = scan(text)
    dd_findings = [f for f in findings if f.type == "datadog_api_key"]
    assert len(dd_findings) == 1


def test_datadog_app_key():
    """Datadog app keys with DD context should be detected."""
    text = "DD_APP_KEY=abcdef0123456789abcdef0123456789abcdef01"
    findings = scan(text)
    dd_findings = [f for f in findings if f.type == "datadog_app_key"]
    assert len(dd_findings) == 1


def test_datadog_hex_without_context_not_matched():
    """32-char hex without Datadog context should not trigger datadog_api_key."""
    text = "hash=abcdef0123456789abcdef0123456789"
    findings = scan(text)
    dd_findings = [f for f in findings if f.type == "datadog_api_key"]
    assert len(dd_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 2: PAGERDUTY
# ═══════════════════════════════════════════════

def test_pagerduty_api_key():
    """PagerDuty API keys with u+ prefix and PD context should be detected."""
    text = "PAGERDUTY_API_KEY=u+AbCdEfGhIj-kl-m012"
    findings = scan(text)
    pd_findings = [f for f in findings if f.type == "pagerduty_api_key"]
    assert len(pd_findings) == 1


# ═══════════════════════════════════════════════
# BATCH 2: AIRTABLE
# ═══════════════════════════════════════════════

def test_airtable_api_key():
    """Airtable PATs with pat prefix + dot + hex should be detected."""
    text = "AIRTABLE_API_KEY=patABCDEFGHIJKLmn.abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    findings = scan(text)
    at_findings = [f for f in findings if f.type == "airtable_api_key"]
    assert len(at_findings) == 1
    assert at_findings[0].confidence >= 0.93


def test_airtable_pat_without_dot_not_matched():
    """pat prefix without the dot-hex structure should not match airtable_api_key."""
    text = "pattern_match_config=patABCDEFGHIJKLmn"
    findings = scan(text)
    at_findings = [f for f in findings if f.type == "airtable_api_key"]
    assert len(at_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 2: NUGET
# ═══════════════════════════════════════════════

def test_nuget_api_key():
    """NuGet API keys with oy2 prefix should be detected."""
    text = "NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz0123456789abcdefg"
    findings = scan(text)
    ng_findings = [f for f in findings if f.type == "nuget_api_key"]
    assert len(ng_findings) == 1


def test_nuget_oy2_too_short():
    """Short oy2 strings should not match nuget_api_key."""
    text = "oy2short"
    findings = scan(text)
    ng_findings = [f for f in findings if f.type == "nuget_api_key"]
    assert len(ng_findings) == 0


# ═══════════════════════════════════════════════
# FALSE POSITIVE TESTS (BATCH 1 PATTERNS)
# ═══════════════════════════════════════════════

def test_notion_secret_prefix_too_short():
    """Strings starting with secret_ but too short should not match notion_api_key."""
    text = "secret_tooshort1234"
    findings = scan(text)
    notion_findings = [f for f in findings if f.type == "notion_api_key"]
    assert len(notion_findings) == 0, "False positive on short secret_ string"


def test_notion_secret_in_prose():
    """The word 'secret_' in documentation should not trigger notion_api_key."""
    text = "The secret_key field is used for HMAC signing."
    findings = scan(text)
    notion_findings = [f for f in findings if f.type == "notion_api_key"]
    assert len(notion_findings) == 0


def test_hf_prefix_too_short():
    """Short hf_ strings should not match huggingface_token."""
    text = "hf_short"
    findings = scan(text)
    hf_findings = [f for f in findings if f.type == "huggingface_token"]
    assert len(hf_findings) == 0


def test_gsk_prefix_too_short():
    """Short gsk_ strings should not match groq_api_key."""
    text = "gsk_notlongenoughtobearealtokenvalue"
    findings = scan(text)
    groq_findings = [f for f in findings if f.type == "groq_api_key"]
    assert len(groq_findings) == 0


def test_npm_prefix_too_short():
    """Short npm_ strings should not match npm_token."""
    text = "npm_install is not a token"
    findings = scan(text)
    npm_findings = [f for f in findings if f.type == "npm_token"]
    assert len(npm_findings) == 0


def test_vault_hvs_too_short():
    """Short hvs. strings should not match vault_token."""
    text = "hvs.tooshort"
    findings = scan(text)
    vault_findings = [f for f in findings if f.type == "vault_token"]
    assert len(vault_findings) == 0


def test_doppler_dp_not_token():
    """Strings with dp. but wrong format should not match doppler_token."""
    text = "dp.something.else"
    findings = scan(text)
    dp_findings = [f for f in findings if f.type == "doppler_token"]
    assert len(dp_findings) == 0


def test_alibaba_ltai_too_short():
    """LTAI followed by too few chars should not match alibaba_access_key."""
    text = "LTAIshort"
    findings = scan(text)
    ali_findings = [f for f in findings if f.type == "alibaba_access_key"]
    assert len(ali_findings) == 0


def test_fly_fo1_wrong_length():
    """fo1_ followed by wrong-length string should not match fly_api_token."""
    text = "fo1_tooshort"
    findings = scan(text)
    fly_findings = [f for f in findings if f.type == "fly_api_token"]
    assert len(fly_findings) == 0


def test_linear_lin_api_too_short():
    """Short lin_api_ strings should not match linear_api_key."""
    text = "lin_api_short"
    findings = scan(text)
    lin_findings = [f for f in findings if f.type == "linear_api_key"]
    assert len(lin_findings) == 0


def test_grafana_glsa_wrong_format():
    """glsa_ without the underscore-hex suffix should not match grafana_api_key."""
    text = "glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    findings = scan(text)
    gf_findings = [f for f in findings if f.type == "grafana_api_key"]
    assert len(gf_findings) == 0


def test_pypi_wrong_prefix():
    """pypi- without the AgEIcHlwaS5vcmc prefix should not match pypi_token."""
    text = "pypi-somethingrandom1234567890abcdef1234567890abcdef12345678"
    findings = scan(text)
    pypi_findings = [f for f in findings if f.type == "pypi_token"]
    assert len(pypi_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: IBM CLOUD
# ═══════════════════════════════════════════════

def test_ibm_cloud_api_key():
    """IBM Cloud API keys with IBM context should be detected."""
    text = "IBM_API_KEY=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_ABCDEF"
    findings = scan(text)
    ibm_findings = [f for f in findings if f.type == "ibm_cloud_api_key"]
    assert len(ibm_findings) == 1
    assert ibm_findings[0].severity == "high"


def test_ibm_cloud_44char_without_context_not_matched():
    """44-char string without IBM context should not trigger ibm_cloud_api_key."""
    text = "SOME_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_ABCDEF"
    findings = scan(text)
    ibm_findings = [f for f in findings if f.type == "ibm_cloud_api_key"]
    assert len(ibm_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: FIGMA
# ═══════════════════════════════════════════════

def test_figma_pat():
    """Figma PATs with UUID-like format and Figma context should be detected."""
    text = "FIGMA_TOKEN=123456-abcdef01-2345-6789-abcd-ef0123456789"
    findings = scan(text)
    fg_findings = [f for f in findings if f.type == "figma_pat"]
    assert len(fg_findings) == 1
    assert fg_findings[0].severity == "high"


def test_figma_uuid_without_context_not_matched():
    """UUID-like string without Figma context should not trigger figma_pat."""
    text = "SESSION_ID=123456-abcdef01-2345-6789-abcd-ef0123456789"
    findings = scan(text)
    fg_findings = [f for f in findings if f.type == "figma_pat"]
    assert len(fg_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: AUTH0
# ═══════════════════════════════════════════════

def test_auth0_management_token():
    """Auth0 management tokens (JWT with auth0 context) should be detected."""
    text = "AUTH0_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDEyMzQ1Njc4OTAifQ.ABC123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    findings = scan(text)
    a0_findings = [f for f in findings if f.type == "auth0_management_token"]
    assert len(a0_findings) == 1
    assert a0_findings[0].severity == "critical"


def test_auth0_jwt_without_context_not_matched():
    """JWT without auth0 context should not trigger auth0_management_token."""
    text = "TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tLyIsInN1YiI6InVzZXJ8MTIzNDU2Nzg5MCJ9.ABC123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    findings = scan(text)
    a0_findings = [f for f in findings if f.type == "auth0_management_token"]
    assert len(a0_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: SUPABASE
# ═══════════════════════════════════════════════

def test_supabase_service_key():
    """Supabase service role keys (HS256 JWT with supabase context) should be detected."""
    text = "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2QxMjM0ZWZnaCIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
    findings = scan(text)
    sb_findings = [f for f in findings if f.type == "supabase_service_key"]
    assert len(sb_findings) == 1
    assert sb_findings[0].severity == "critical"


def test_supabase_jwt_without_context_not_matched():
    """HS256 JWT without supabase context should not trigger supabase_service_key."""
    text = "TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJvdGhlci1zZXJ2aWNlIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
    findings = scan(text)
    sb_findings = [f for f in findings if f.type == "supabase_service_key"]
    assert len(sb_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: ETHEREUM
# ═══════════════════════════════════════════════

def test_ethereum_private_key():
    """Ethereum private keys (0x + 64 hex with ETH context) should be detected."""
    text = "ETH_PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe512961708279f73ec0b1a1b287cc58"
    findings = scan(text)
    eth_findings = [f for f in findings if f.type == "ethereum_private_key"]
    assert len(eth_findings) == 1
    assert eth_findings[0].severity == "critical"


def test_ethereum_hex_without_context_not_matched():
    """0x + 64 hex without Ethereum context should not trigger ethereum_private_key."""
    text = "HASH=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    findings = scan(text)
    eth_findings = [f for f in findings if f.type == "ethereum_private_key"]
    assert len(eth_findings) == 0


# ═══════════════════════════════════════════════
# BATCH 3: BITCOIN
# ═══════════════════════════════════════════════

def test_bitcoin_wif_key():
    """Bitcoin WIF keys with BTC context should be detected."""
    text = "BTC_PRIVATE_KEY=5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    findings = scan(text)
    btc_findings = [f for f in findings if f.type == "bitcoin_wif_key"]
    assert len(btc_findings) == 1
    assert btc_findings[0].severity == "critical"


def test_bitcoin_wif_without_context_not_matched():
    """Base58 string without Bitcoin context should not trigger bitcoin_wif_key."""
    text = "DATA=5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    findings = scan(text)
    btc_findings = [f for f in findings if f.type == "bitcoin_wif_key"]
    assert len(btc_findings) == 0


# ═══════════════════════════════════════════════
# REDACTION
# ═══════════════════════════════════════════════

def test_redaction_label_style():
    from app.engine.redactor import redact
    
    text = "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284\nSTRIPE_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd"
    findings = scan(text)
    redacted_text, redaction_map = redact(text, findings, style="label")
    
    assert "AKIAJGKJHSKLDJFH3284" not in redacted_text
    assert "sk_live_" not in redacted_text
    assert "[AWS_ACCESS_KEY_REDACTED]" in redacted_text
    assert "[STRIPE_LIVE_SECRET_KEY_REDACTED]" in redacted_text


def test_redaction_mask_style():
    from app.engine.redactor import redact
    
    text = "key=sk_live_51H3aKLkdsjfhDKJSH38djfhksd"
    findings = scan(text)
    redacted_text, _ = redact(text, findings, style="mask")
    
    assert "sk_l" in redacted_text  # first 4 chars preserved
    assert "djfhksd" not in redacted_text  # rest should be masked


# ═══════════════════════════════════════════════
# MULTI-SECRET SCAN
# ═══════════════════════════════════════════════

def test_multiple_secrets_in_one_text():
    """A realistic .env file with multiple secrets."""
    text = """
AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://admin:p4ssw0rd@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh
SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs
SLACK_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx
"""
    findings = scan(text, min_confidence=0.1)
    types_found = {f.type for f in findings}
    
    assert "aws_access_key" in types_found
    assert "stripe_live_secret_key" in types_found
    assert "github_pat_classic" in types_found
    assert "sendgrid_api_key" in types_found
    assert "slack_bot_token" in types_found
    assert "postgres_connection_string" in types_found


def test_clean_text_no_findings():
    """Normal text without secrets should return no findings."""
    text = """
Hello, this is a normal email about the project meeting next Tuesday.
Please review the quarterly report and let me know your thoughts.
The budget for Q3 is $1.2 million, and we need to allocate resources.
Contact me at thomas@example.com or call 555-0123.
"""
    findings = scan(text)
    assert len(findings) == 0, f"False positives found: {[f.type for f in findings]}"


# ═══════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    tests = [
        test_aws_access_key_true_positives,
        test_aws_access_key_true_negatives,
        test_aws_access_key_test_value_flagged,
        test_stripe_live_key_detected,
        test_stripe_test_key_lower_severity,
        test_stripe_webhook_secret,
        test_github_classic_pat,
        test_github_fine_grained_pat,
        test_gitlab_pat,
        test_slack_bot_token,
        test_slack_webhook,
        test_sendgrid_api_key,
        test_postgres_connection_string,
        test_mongodb_connection_string,
        test_rsa_private_key,
        test_jwt_token_standalone,
        test_jwt_in_bearer_header,
        test_redaction_label_style,
        test_redaction_mask_style,
        test_multiple_secrets_in_one_text,
        test_clean_text_no_findings,
    ]
    
    passed = 0
    failed = 0
    
    for test_fn in tests:
        try:
            test_fn()
            print(f"  ✓ {test_fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {test_fn.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ {test_fn.__name__}: EXCEPTION — {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")

    if failed > 0:
        sys.exit(1)


# ═══════════════════════════════════════════════
# XAI (GROK) — NEW
# ═══════════════════════════════════════════════

def test_xai_api_key_true_positives():
    cases = [
        "XAI_API_KEY=xai-AbCdEfGhIjKlMnOpQrStUv",
        'export XAI_KEY="xai-1234567890AbCdEfGhIjKl"',
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        xai_findings = [f for f in findings if f.type == "xai_api_key"]
        assert len(xai_findings) >= 1, f"Failed to detect xAI key in: {text}"


def test_xai_api_key_true_negatives():
    cases = [
        "xai-short",  # too short
        "The xai-protocol is used for communication",  # not a key
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.3)
        xai_findings = [f for f in findings if f.type == "xai_api_key"]
        assert len(xai_findings) == 0, f"False positive on: {text}"


# ═══════════════════════════════════════════════
# ELEVENLABS — NEW
# ═══════════════════════════════════════════════

def test_elevenlabs_api_key_true_positives():
    cases = [
        "ELEVENLABS_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "xi-api-key: f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        el_findings = [f for f in findings if f.type == "elevenlabs_api_key"]
        assert len(el_findings) >= 1, f"Failed to detect ElevenLabs key in: {text}"


def test_elevenlabs_hex_without_context_not_matched():
    text = "random_value=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    findings = scan(text, min_confidence=0.3)
    el_findings = [f for f in findings if f.type == "elevenlabs_api_key"]
    assert len(el_findings) == 0


# ═══════════════════════════════════════════════
# ASSEMBLYAI — NEW
# ═══════════════════════════════════════════════

def test_assemblyai_api_key_true_positives():
    cases = [
        "ASSEMBLYAI_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "assemblyai_key = f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        aa_findings = [f for f in findings if f.type == "assemblyai_api_key"]
        assert len(aa_findings) >= 1, f"Failed to detect AssemblyAI key in: {text}"


# ═══════════════════════════════════════════════
# DEEPGRAM — NEW
# ═══════════════════════════════════════════════

def test_deepgram_api_key_true_positives():
    cases = [
        "DEEPGRAM_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "deepgram_key = f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        dg_findings = [f for f in findings if f.type == "deepgram_api_key"]
        assert len(dg_findings) >= 1, f"Failed to detect Deepgram key in: {text}"


# ═══════════════════════════════════════════════
# LANGFUSE — NEW
# ═══════════════════════════════════════════════

def test_langfuse_secret_key_true_positives():
    cases = [
        "LANGFUSE_SECRET_KEY=sk-lf-AbCdEfGhIjKlMnOpQrStUv",
        'key = "sk-lf-1234567890-AbCdEfGhIjKl"',
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        lf_findings = [f for f in findings if f.type == "langfuse_secret_key"]
        assert len(lf_findings) >= 1, f"Failed to detect LangFuse key in: {text}"


def test_langfuse_short_not_matched():
    text = "sk-lf-short"
    findings = scan(text, min_confidence=0.3)
    lf_findings = [f for f in findings if f.type == "langfuse_secret_key"]
    assert len(lf_findings) == 0


# ═══════════════════════════════════════════════
# MISTRAL — NEW
# ═══════════════════════════════════════════════

def test_mistral_api_key_true_positives():
    cases = [
        "MISTRAL_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        "mistral_key = Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        m_findings = [f for f in findings if f.type == "mistral_api_key"]
        assert len(m_findings) >= 1, f"Failed to detect Mistral key in: {text}"


# ═══════════════════════════════════════════════
# DISCORD WEBHOOK — NEW
# ═══════════════════════════════════════════════

def test_discord_webhook_url_true_positives():
    cases = [
        "https://discord.com/api/webhooks/12345678901234567/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "https://discordapp.com/api/webhooks/98765432109876543/ZyXwVuTsRqPoNmLkJiHgFeDcBaZyXwVuTsRqPoNmLkJiHgFeDcBaZyXwVuTs12",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        dw_findings = [f for f in findings if f.type == "discord_webhook_url"]
        assert len(dw_findings) >= 1, f"Failed to detect Discord webhook in: {text}"


# ═══════════════════════════════════════════════
# TEAMS WEBHOOK — NEW
# ═══════════════════════════════════════════════

def test_teams_webhook_url_true_positives():
    text = "https://myorg.webhook.office.com/webhookb2/a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6@f1e2d3c4-b5a6-f7e8-d9c0-b1a2f3e4d5c6/IncomingWebhook/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/f1e2d3c4-b5a6-f7e8-d9c0-b1a2f3e4d5c6"
    findings = scan(text, min_confidence=0.1)
    tw_findings = [f for f in findings if f.type == "teams_webhook_url"]
    assert len(tw_findings) >= 1


# ═══════════════════════════════════════════════
# MATTERMOST — NEW
# ═══════════════════════════════════════════════

def test_mattermost_token_true_positives():
    text = "MATTERMOST_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3"
    findings = scan(text, min_confidence=0.1)
    mm_findings = [f for f in findings if f.type == "mattermost_token"]
    assert len(mm_findings) >= 1


# ═══════════════════════════════════════════════
# OKTA — NEW
# ═══════════════════════════════════════════════

def test_okta_api_token_true_positives():
    text = "OKTA_API_TOKEN=00AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd"
    findings = scan(text, min_confidence=0.1)
    ok_findings = [f for f in findings if f.type == "okta_api_token"]
    assert len(ok_findings) >= 1


# ═══════════════════════════════════════════════
# BUILDKITE — NEW
# ═══════════════════════════════════════════════

def test_buildkite_token_true_positives():
    text = "BUILDKITE_TOKEN=bkua_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd"
    findings = scan(text)
    bk_findings = [f for f in findings if f.type == "buildkite_token"]
    assert len(bk_findings) == 1


def test_buildkite_wrong_prefix_not_matched():
    text = "bkub_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd"
    findings = scan(text, min_confidence=0.3)
    bk_findings = [f for f in findings if f.type == "buildkite_token"]
    assert len(bk_findings) == 0


# ═══════════════════════════════════════════════
# RAILWAY — NEW
# ═══════════════════════════════════════════════

def test_railway_token_true_positives():
    text = "RAILWAY_TOKEN=a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6"
    findings = scan(text, min_confidence=0.1)
    rw_findings = [f for f in findings if f.type == "railway_token"]
    assert len(rw_findings) >= 1


# ═══════════════════════════════════════════════
# RAZORPAY — NEW
# ═══════════════════════════════════════════════

def test_razorpay_key_true_positives():
    cases = [
        "RAZORPAY_KEY=rzp_live_AbCdEfGhIjKlMn",
        "rzp_test_ZyXwVuTsRqPoNm",
    ]
    for text in cases:
        findings = scan(text, min_confidence=0.1)
        rz_findings = [f for f in findings if f.type == "razorpay_key"]
        assert len(rz_findings) >= 1, f"Failed to detect Razorpay key in: {text}"


def test_razorpay_wrong_prefix_not_matched():
    text = "rzp_dev_AbCdEfGhIjKlMn"
    findings = scan(text, min_confidence=0.3)
    rz_findings = [f for f in findings if f.type == "razorpay_key"]
    assert len(rz_findings) == 0


# ═══════════════════════════════════════════════
# CONTEXT VARIETY TESTS
# ═══════════════════════════════════════════════
# Tests key patterns embedded in different real-world contexts:
# JSON, YAML, .env, shell, logs, Python code


CONTEXT_TESTS = [
    # (pattern_id, secret_value, context_templates)
    (
        "aws_access_key",
        "AKIAJGKJHSKLDJFH3284",
        [
            '{"aws_access_key_id": "AKIAJGKJHSKLDJFH3284"}',
            "aws_access_key_id: AKIAJGKJHSKLDJFH3284",
            "export AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284",
            "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284",
            '[INFO] Using key AKIAJGKJHSKLDJFH3284 for auth',
            'aws_key = "AKIAJGKJHSKLDJFH3284"',
        ],
    ),
    (
        "stripe_live_secret_key",
        "sk_live_51H3aKLkdsjfhDKJSH38djfhksd",
        [
            '{"stripe_key": "sk_live_51H3aKLkdsjfhDKJSH38djfhksd"}',
            "stripe_key: sk_live_51H3aKLkdsjfhDKJSH38djfhksd",
            "export STRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd",
            "STRIPE_SECRET_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd",
            'curl -H "Authorization: Bearer sk_live_51H3aKLkdsjfhDKJSH38djfhksd"',
            'key = "sk_live_51H3aKLkdsjfhDKJSH38djfhksd"',
        ],
    ),
    (
        "github_pat_classic",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu",
        [
            '{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu"}',
            "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu",
            "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu",
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu",
            'git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZzyxwvu@github.com/repo',
        ],
    ),
    (
        "slack_bot_token",
        "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx",
        [
            '{"slack_token": "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx"}',
            "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx",
            'token = "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx"',
        ],
    ),
    (
        "sendgrid_api_key",
        "SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc",
        [
            '{"sendgrid_key": "SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc"}',
            "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc",
            '[DEBUG] Sending with SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc',
        ],
    ),
]


@pytest.mark.parametrize(
    "pattern_id,secret,contexts",
    CONTEXT_TESTS,
    ids=[t[0] for t in CONTEXT_TESTS],
)
def test_pattern_in_varied_contexts(pattern_id, secret, contexts):
    """Patterns should be detected regardless of surrounding context format."""
    for ctx in contexts:
        findings = scan(ctx, min_confidence=0.1)
        matched = [f for f in findings if f.type == pattern_id]
        assert len(matched) >= 1, (
            f"Failed to detect {pattern_id} in context: {ctx[:80]}..."
        )
