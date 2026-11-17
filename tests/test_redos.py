"""
Superlinear-regex guard for the whole pattern registry.

Every registered pattern is timed against a set of repeated-unit inputs — the
shapes that expose quadratic backtracking (whitespace runs, repeated prefixes,
separator runs). A linear pattern handles 8 KB of any of these in well under a
millisecond; the budget below is ~100x that, so this only trips on genuinely
superlinear behaviour, not on a slow CI machine.

Background: `pi_fake_assistant_turn` shipped with `(?:^|\\n)\\s*`, which took
~0.9 s on 8 KB of newlines and ~16 minutes (extrapolated) on a 256 KB request.
"""

import time

import pytest

from app.engine.patterns.registry import PATTERN_REGISTRY

INPUT_BYTES = 8192
BUDGET_SECONDS = 0.25

# Repeated to INPUT_BYTES. Keep this list generic: per-pattern adversarial
# prefixes belong in the pattern's own tests.
REPEAT_UNITS = [
    "\n",
    " ",
    "\t",
    " \n",
    "\r\n",
    "a",
    "A",
    "0",
    "a ",
    "a\n",
    "=",
    "a=",
    "-",
    "a-",
    "a.",
    "/",
    "a/",
    "://",
    "a:a@",
    '"',
    "'",
    "eyJ",
    "aB1_-",
    "key=",
    "token: ",
    "ignore ",
    "you are ",
    "assistant ",
    "-----BEGIN ",
]


@pytest.mark.parametrize("unit", REPEAT_UNITS, ids=[repr(u) for u in REPEAT_UNITS])
def test_no_pattern_is_superlinear_on_repeated_input(unit: str) -> None:
    text = (unit * (INPUT_BYTES // len(unit) + 1))[:INPUT_BYTES]
    slow: list[tuple[str, float]] = []

    for pattern in PATTERN_REGISTRY:
        t0 = time.perf_counter()
        for _ in pattern.regex.finditer(text):
            pass
        elapsed = time.perf_counter() - t0
        if elapsed > BUDGET_SECONDS:
            slow.append((pattern.id, round(elapsed, 3)))

    assert not slow, (
        f"superlinear on {INPUT_BYTES} bytes of repeated {unit!r} "
        f"(budget {BUDGET_SECONDS}s): {slow}"
    )


def test_fake_assistant_turn_still_matches_after_blank_lines() -> None:
    """The linear rewrite must keep matching labels after blank/indented lines."""
    pattern = next(p for p in PATTERN_REGISTRY if p.id == "pi_fake_assistant_turn")
    for text in (
        "Assistant: sure",
        "hello\nAssistant: sure",
        "hello\n\n\n   Assistant: sure",
        "hello\r\n\tClaude > ok",
        "hello\n \n \n  GPT: done",
    ):
        assert pattern.regex.search(text), text
    assert not pattern.regex.search("my assistant: is helpful")
