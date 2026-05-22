"""
ClassiFinder — False Positive Filter Tests

Tests the wordlist-based false positive detection system.
Run with: python -m pytest tests/test_false_positives.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine.false_positives import is_known_false_positive, _load_wordlist


# ═══════════════════════════════════════════════
# DEFAULT FALSE POSITIVES
# ═══════════════════════════════════════════════


def test_default_false_positives_caught():
    """Strings containing default false positive terms should be caught."""
    cases = [
        ("example_api_key_here", "example"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxx"),
        ("aaaaaa1234567890zzzzwwww", "aaaaaa"),
        ("my_placeholder_value_1234", "placeholder"),
        ("sk_test_foobar_1234567890zzzzww", "foobar"),
        ("replace_me_with_real_key", "replace_me"),
    ]
    for value, expected_term in cases:
        is_fp, reason = is_known_false_positive(value)
        assert is_fp, f"Expected FP for '{value}' but got pass-through"
        assert expected_term in reason, f"Expected '{expected_term}' in reason, got: {reason}"


def test_default_false_positives_case_insensitive():
    """Default FP check should be case-insensitive."""
    is_fp, _ = is_known_false_positive("EXAMPLE_KEY_12345678")
    assert is_fp

    is_fp, _ = is_known_false_positive("MyPlaceholderToken99")
    assert is_fp


# ═══════════════════════════════════════════════
# WORDLIST FALSE POSITIVES
# ═══════════════════════════════════════════════


def test_wordlist_false_positives_caught():
    """Strings containing wordlist terms should be caught."""
    cases = [
        "mysecret_token_value_12345678",
        "dummykey_abcdefghijklmnopqrst",
        "sandbox_api_key_1234567890ab",
        "faketoken_9876543210abcdefgh",
    ]
    for value in cases:
        is_fp, reason = is_known_false_positive(value)
        assert is_fp, f"Expected FP for '{value}' but got pass-through. Reason: {reason}"


def test_wordlist_loads():
    """The wordlist file should exist and load correctly."""
    wordlist = _load_wordlist()
    assert len(wordlist) > 30, f"Wordlist too small: {len(wordlist)} terms"
    assert "mysecret" in wordlist
    assert "faketoken" in wordlist
    assert "sandbox" in wordlist


# ═══════════════════════════════════════════════
# REAL SECRETS (SHOULD PASS THROUGH)
# ═══════════════════════════════════════════════


def test_real_secrets_pass_through():
    """High-entropy random strings should NOT be caught as false positives."""
    cases = [
        "zB3kE6gH9jK2mN5pQ8sT1vW4yZ7cR0fB3wE6gH9j",
        "sk_live_AbCdEfGhIjKlMnOpQrStUvWxYzAb",
        "ghp_ZYXWVUTSRQPONMLKJIHGFzyxwvutsrqpo",
        "SG.zywxvutsrqponmlkjihgfe.ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyw",
        "AKIAABCDEFGHIJKLMNOP",
        "xoxb-1234567890-1234567890-ZbKdRfGhIjKlMnOpQrStUvWx",
    ]
    for value in cases:
        is_fp, reason = is_known_false_positive(value)
        assert not is_fp, f"False positive on real-looking secret '{value}': {reason}"


def test_prefix_anchored_values_pass_through():
    """Values with provider-specific prefixes should not be caught."""
    cases = [
        "sk-ant-api03-zywxvutsrqponmlkjihgf1234567890ZYXWVUTSRQP",
        "hf_ZbKdRfGhIjKlMnOpQrStUvWxYz123456",
        "r8_ZbKdRfGhIjKlMnOpQrStUvWxYz1234567890",
        "gsk_ZbKdRfGhIjKlMnOpQrStUvWxYz1234567890ZbKdRfGhIjKlMnOpQ",
    ]
    for value in cases:
        is_fp, reason = is_known_false_positive(value)
        assert not is_fp, f"False positive on prefix-anchored value '{value}': {reason}"


# ═══════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════


def test_empty_string():
    """Empty string should not be a false positive."""
    is_fp, _ = is_known_false_positive("")
    assert not is_fp


def test_short_string():
    """Short strings without FP terms should pass through."""
    is_fp, _ = is_known_false_positive("abc")
    assert not is_fp
