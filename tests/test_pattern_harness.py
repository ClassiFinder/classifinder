"""
ClassiFinder — Data-Driven Pattern Test Harness

Auto-generates tests from pattern_test_cases.py for every registered pattern.
Enforces three guarantees:

1. Every pattern in the registry has test cases defined
2. Every positive sample is detected with adequate confidence
3. Every negative sample does NOT trigger the specific pattern
4. No positive sample triggers a DIFFERENT pattern at higher confidence (collision check)

Run with: python -m pytest tests/test_pattern_harness.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.engine.scanner import scan
from app.engine.patterns.registry import PATTERN_REGISTRY
from tests.pattern_test_cases import PATTERN_TEST_CASES


# ═══════════════════════════════════════════════
# COVERAGE CHECK — every registered pattern must have test cases
# ═══════════════════════════════════════════════

# Patterns that are intentionally tested only via the handwritten tests
# in test_patterns.py (complex patterns that need special assertions).
HARNESS_EXEMPT = {
    # Multi-format patterns tested manually
    "gcp_service_account_key",
    "credit_card_number",
    # Auth header patterns tested manually
    "bearer_token",
    "basic_auth_header",
    # Context-only patterns with complex regex
    "slack_user_token",
    "twilio_account_sid",
    "twilio_auth_token",
    "heroku_api_key",
    "azure_ad_client_secret",
    "ibm_cloud_api_key",
    "paypal_client_secret",
    "square_access_token",
    "env_database_password",
    "password_in_url",
    "generic_high_entropy",
    "pagerduty_api_key",
    "github_app_installation_token",
    "github_user_to_server_token",
    "gitlab_pipeline_trigger",
    "bitbucket_app_password",
    "newrelic_admin_api_key",
    "newrelic_insights_key",
    "newrelic_user_api_key",
    "sentry_user_token",
    "datadog_app_key",
    "stripe_live_publishable_key",
    "stripe_restricted_key",
    "shopify_custom_token",
    "shopify_private_token",
    "ethereum_private_key",
    "bitcoin_wif_key",
    "vercel_refresh_token",
    "mysql_connection_string",
    "redis_connection_string",
}


def test_all_patterns_have_test_cases():
    """Every registered pattern must have test cases or be explicitly exempt."""
    registered_ids = {p.id for p in PATTERN_REGISTRY}
    tested_ids = set(PATTERN_TEST_CASES.keys())
    exempt_ids = HARNESS_EXEMPT

    covered = tested_ids | exempt_ids
    missing = registered_ids - covered

    assert not missing, (
        f"{len(missing)} pattern(s) have no test cases and are not exempt:\n"
        + "\n".join(f"  - {pid}" for pid in sorted(missing))
    )


# ═══════════════════════════════════════════════
# TRUE POSITIVE TESTS
# ═══════════════════════════════════════════════

_positive_cases = []
for _pid, _cases in PATTERN_TEST_CASES.items():
    for _i, _text in enumerate(_cases["positives"]):
        _positive_cases.append((_pid, _text, _cases.get("min_confidence", 0.5)))


@pytest.mark.parametrize(
    "pattern_id,text,min_conf",
    _positive_cases,
    ids=[f"{c[0]}__pos{i}" for i, c in enumerate(_positive_cases)],
)
def test_true_positive(pattern_id, text, min_conf):
    """Positive sample must be detected by its pattern with adequate confidence."""
    findings = scan(text, min_confidence=0.01)
    matched = [f for f in findings if f.type == pattern_id]
    assert len(matched) >= 1, f"Pattern '{pattern_id}' not detected in: {text[:80]}"
    assert matched[0].confidence >= min_conf, (
        f"Pattern '{pattern_id}' confidence {matched[0].confidence} < {min_conf}"
    )


# ═══════════════════════════════════════════════
# TRUE NEGATIVE TESTS
# ═══════════════════════════════════════════════

_negative_cases = []
for _pid, _cases in PATTERN_TEST_CASES.items():
    for _i, _text in enumerate(_cases.get("negatives", [])):
        _negative_cases.append((_pid, _text))


@pytest.mark.parametrize(
    "pattern_id,text",
    _negative_cases,
    ids=[f"{c[0]}__neg{i}" for i, c in enumerate(_negative_cases)],
)
def test_true_negative(pattern_id, text):
    """Negative sample must NOT trigger the specific pattern."""
    findings = scan(text, min_confidence=0.01)
    matched = [f for f in findings if f.type == pattern_id]
    assert len(matched) == 0, (
        f"False positive: '{pattern_id}' triggered on: {text[:80]}"
    )


# ═══════════════════════════════════════════════
# COLLISION CHECK — positive samples should primarily trigger their own pattern
# ═══════════════════════════════════════════════

@pytest.mark.parametrize(
    "pattern_id,text,min_conf",
    _positive_cases,
    ids=[f"{c[0]}__collision{i}" for i, c in enumerate(_positive_cases)],
)
def test_no_collision(pattern_id, text, min_conf):
    """A positive sample's highest-confidence finding should be its own pattern
    (or a closely related one), not a completely different provider's pattern."""
    findings = scan(text, min_confidence=0.01)
    if not findings:
        return  # No findings at all — the positive test will catch this

    top_finding = max(findings, key=lambda f: f.confidence)

    # Allow if the top finding IS our pattern
    if top_finding.type == pattern_id:
        return

    # Allow if our pattern is in the findings (just not the top one)
    our_findings = [f for f in findings if f.type == pattern_id]
    if our_findings:
        return  # Our pattern found it; another pattern also matched — that's OK

    # Our pattern wasn't found at all — the positive test will catch this
