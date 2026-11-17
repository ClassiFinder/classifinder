"""
Context snippets must never carry a full secret.

A finding's `context` shows ~40 characters either side of the match. Secrets
cluster (.env files, credential pairs), so that window routinely contains a
second secret. These tests pin the rule that every span the scanner matched is
masked inside every context — including spans the caller filtered out with
`types`, and spans that scored below `min_confidence`.

Fixture values are built by concatenation so no contiguous credential-shaped
literal sits in the repo.
"""

from app.engine.scanner import _extract_context, _merge_spans, scan

# Synthetic, correctly shaped, not known test values.
GITHUB_PAT = "ghp_" + "R7kQ2mX9vB4nL8sT1wZ6yC3dF5hJ0pA7uE2i"
AWS_KEY_ID = "AKIA" + "Q3EGUL7XNPT5WZ2B"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def _by_type(findings: list, type_id: str):
    matches = [f for f in findings if f.type == type_id]
    assert matches, f"expected a {type_id} finding, got {[f.type for f in findings]}"
    return matches[0]


def test_neighbouring_secret_is_masked_in_context() -> None:
    text = f"token: {GITHUB_PAT} {AWS_KEY_ID}\n"
    findings = scan(text)

    github = _by_type(findings, "github_pat_classic")
    aws = _by_type(findings, "aws_access_key")

    for f in findings:
        assert GITHUB_PAT not in f.context
        assert AWS_KEY_ID not in f.context
    # Each context still shows its own masked preview and the neighbour's.
    assert github.value_preview in github.context
    assert aws.value_preview in github.context
    assert aws.value_preview in aws.context


def test_no_long_fragment_of_neighbour_survives() -> None:
    """A neighbour clipped by the window edge must not leave a long raw tail."""
    text = f"GITHUB_TOKEN={GITHUB_PAT}\nSTRIPE_KEY={STRIPE_KEY}\n"
    for f in scan(text):
        for secret in (GITHUB_PAT, STRIPE_KEY):
            for i in range(len(secret) - 12 + 1):
                assert secret[i : i + 12] not in f.context, (f.type, f.context)


def test_type_filter_does_not_expose_unselected_secret() -> None:
    text = f"id={AWS_KEY_ID} token={GITHUB_PAT}\n"
    findings = scan(text, types=["aws_access_key"])

    assert [f.type for f in findings] == ["aws_access_key"]
    assert GITHUB_PAT not in findings[0].context
    assert AWS_KEY_ID not in findings[0].context


def test_type_filter_without_context_still_filters() -> None:
    text = f"id={AWS_KEY_ID} token={GITHUB_PAT}\n"
    findings = scan(text, types=["aws_access_key"], include_context=False)

    assert [f.type for f in findings] == ["aws_access_key"]
    assert findings[0].context is None


def test_type_filter_masks_neighbour_that_needs_a_key_name() -> None:
    """Context-keyed patterns need text before the window to match at all."""
    password = "Xk9mQ2pLw7Rt4Zs8"
    text = f"POSTGRES_PASSWORD={password}\nAWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
    findings = scan(text, types=["aws_access_key"])

    assert [f.type for f in findings] == ["aws_access_key"]
    assert password not in findings[0].context


def test_type_filter_mask_pass_is_limited_to_finding_regions() -> None:
    """Far-away text is not rescanned: only regions around findings are."""
    from app.engine.scanner import _spans_near_findings

    far_secret_at = 20_000
    text = f"id={AWS_KEY_ID}\n" + "x" * far_secret_at + f" {GITHUB_PAT}\n"
    findings = scan(text, types=["aws_access_key"], include_context=False)

    spans = _spans_near_findings(text, findings, {"aws_access_key"})
    assert all(end < far_secret_at for _, end in spans)

    # With no filter-excluded neighbour nearby, the near one is still caught.
    near = f"id={AWS_KEY_ID} {GITHUB_PAT}\n"
    near_findings = scan(near, types=["aws_access_key"], include_context=False)
    near_spans = _spans_near_findings(near, near_findings, {"aws_access_key"})
    assert (near.index(GITHUB_PAT), near.index(GITHUB_PAT) + len(GITHUB_PAT)) in near_spans


def test_sub_threshold_match_is_masked_in_context() -> None:
    """A known test value scores 0.15 and is not reported, but is still masked."""
    example_key = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"{GITHUB_PAT} {example_key}\n"
    findings = scan(text)

    assert [f.type for f in findings] == ["github_pat_classic"]
    assert example_key not in findings[0].context


def test_single_finding_context_unchanged() -> None:
    text = f"export GITHUB_TOKEN={GITHUB_PAT}  # deploy"
    (with_ctx,) =[f for f in scan(text) if f.type == "github_pat_classic"]
    assert with_ctx.context.startswith("export GITHUB_TOKEN=ghp_****uE2i")
    assert GITHUB_PAT not in with_ctx.context


def test_merge_spans() -> None:
    assert _merge_spans([]) == []
    assert _merge_spans([(5, 9), (0, 3), (2, 6), (20, 25), (9, 10)]) == [(0, 10), (20, 25)]


def test_extract_context_clips_span_to_window() -> None:
    text = "a" * 10 + "SECRETSECRETSECRETSECRET" + "b" * 100
    # Finding at 60..70; another span 10..34 lies partly inside the 40-char window.
    ctx = _extract_context(text, 60, 70, mask_spans=[(10, 34)])
    assert "SECRETSECRET" not in ctx
