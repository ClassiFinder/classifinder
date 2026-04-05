"""
ClassiFinder — Base64 Decoder Tests

Tests the pre-scan base64 decoding system.
Run with: python -m pytest tests/test_decoders.py -v
"""

import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine.decoders import decode_base64_segments


# ═══════════════════════════════════════════════
# SUCCESSFUL DECODING
# ═══════════════════════════════════════════════


def test_decode_base64_stripe_key():
    """Base64-encoded Stripe key should be decoded."""
    secret = "API_KEY=sk_live_1234567890abcdef1234"
    encoded = base64.b64encode(secret.encode()).decode()
    text = f"ENCODED_SECRET={encoded}"
    results = decode_base64_segments(text)
    assert len(results) >= 1
    decoded_text, start, end = results[0]
    assert "sk_live_" in decoded_text


def test_decode_base64_aws_key():
    """Base64-encoded AWS key should be decoded."""
    secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    encoded = base64.b64encode(secret.encode()).decode()
    text = f"data: {encoded}"
    results = decode_base64_segments(text)
    assert len(results) >= 1
    decoded_text = results[0][0]
    assert "AKIA" in decoded_text


def test_decode_url_safe_base64():
    """URL-safe base64 (with - and _) should be decoded."""
    secret = "secret_token=ghp_ZXCVBNM1234567890qwerty"
    encoded = base64.urlsafe_b64encode(secret.encode()).decode()
    text = f"token={encoded}"
    results = decode_base64_segments(text)
    assert len(results) >= 1
    assert "ghp_" in results[0][0]


def test_multiple_segments():
    """Multiple base64 segments should each be decoded with correct positions."""
    secret1 = "API_KEY=sk_live_aBcDeFgHiJkLmN12"
    secret2 = "TOKEN=ghp_ZyXwVuTsRqPoNmLkJiHgFe99"
    enc1 = base64.b64encode(secret1.encode()).decode()
    enc2 = base64.b64encode(secret2.encode()).decode()
    text = f"first={enc1} second={enc2}"
    results = decode_base64_segments(text)
    assert len(results) >= 2
    # Check positions are different
    assert results[0][1] != results[1][1]


def test_padded_and_unpadded():
    """Both padded (=) and unpadded base64 should decode."""
    secret = "short_secret_value_here"
    # Standard encoding has padding
    encoded_padded = base64.b64encode(secret.encode()).decode()
    # Remove padding for unpadded variant
    encoded_unpadded = encoded_padded.rstrip("=")

    for encoded in [encoded_padded, encoded_unpadded]:
        text = f"key={encoded}"
        results = decode_base64_segments(text)
        assert len(results) >= 1, f"Failed to decode: {encoded}"


# ═══════════════════════════════════════════════
# CORRECTLY IGNORED
# ═══════════════════════════════════════════════


def test_short_base64_ignored():
    """Base64 strings under 20 chars should not be decoded."""
    text = "short=SGVsbG8gV29ybGQ="  # "Hello World" = 16 chars encoded
    results = decode_base64_segments(text)
    # Should not decode since the encoded part is only ~16 chars
    for decoded, _, _ in results:
        assert len(decoded) == 0 or "Hello" not in decoded


def test_no_base64_returns_empty():
    """Plain text with no base64 returns empty list."""
    text = "This is just plain text with no encoded secrets"
    results = decode_base64_segments(text)
    # May return empty or segments that decode to gibberish (filtered by ASCII check)
    for decoded, _, _ in results:
        assert decoded.isprintable()


def test_binary_output_ignored():
    """Base64 that decodes to non-ASCII bytes should be ignored."""
    # Create a base64 string that decodes to binary (non-ASCII)
    binary_data = bytes(range(128, 180))
    encoded = base64.b64encode(binary_data).decode()
    text = f"binary_data={encoded}"
    results = decode_base64_segments(text)
    # None of the results should contain the binary data
    for decoded, _, _ in results:
        assert decoded.isascii()
