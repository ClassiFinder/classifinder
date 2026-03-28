# Pattern Quality Testing Framework — Design Spec

**Date:** 2026-03-27
**Status:** Approved
**Scope:** `classifinder-tests/` — new top-level directory in the monorepo

## Problem

ClassiFinder has 50 regex patterns for detecting secrets. The existing test suite (`classifinder/tests/test_patterns.py`, 21 tests) covers a subset with hardcoded true positive/negative cases. There is no systematic way to measure false positive rates, false negative rates, confidence score quality, or cross-engine parity. The no-storage security model means we can't rely on user feedback for pattern strings, so we must test with our own data.

## Design Decisions

These were discussed and agreed upon before writing this spec:

- **Separate directory** (`classifinder-tests/`) rather than inside `classifinder/` — different purpose (pattern quality vs. code correctness), different dependencies, different run cadence.
- **Test both engines** — the API server engine (`classifinder/app/engine/`) and the standalone open-source engine (`classifinder-engine/`). Hard fail on divergence with an allowlist for intentional temporary drift.
- **Dual output** — pytest for CI gates (pass/fail), standalone report scripts for deep analysis (structured JSON).
- **JSON output schema** — all reports conform to Pydantic models so a future UI can consume them directly.
- **Self-documenting corpus** — each corpus file declares expected results in header comments (`# expect: pattern_id`).

## Project Structure

```
classifinder-tests/
  pyproject.toml

  lib/
    __init__.py
    engine_wrapper.py           # unified interface to both engines
    schema.py                   # JSON output schema (Pydantic models)
    pattern_library_parser.py   # parse pattern-library.md into structured data
    comparator.py               # cross-engine parity comparison
    parity_allowlist.py         # known intentional divergences

  corpus/
    benign/
      prose/                    # blog posts, articles, plain english
      code/                     # open-source code without real secrets
      config-templates/         # .env.example, docker-compose templates
      encoded/                  # base64, JWTs from public docs, non-secret high-entropy
    known-secrets/
      cloud/                    # AWS, GCP, Azure synthetic secrets
      payment/                  # Stripe, PayPal synthetic secrets
      vcs/                      # GitHub, GitLab tokens
      comms/                    # Slack, Discord, Twilio
      database/                 # connection strings
      ai/                       # OpenAI, Anthropic, Cohere
      generic/                  # JWTs, bearer tokens, env vars
    adversarial/                # edge cases, near-misses, boundary tests
    README.md                   # manifest: what each dir contains, provenance
    .gitignore                  # large scraped files ignored, curated fixtures committed

  tests/
    conftest.py                 # fixtures: engine instances, parsed pattern library
    test_pattern_library.py     # every pattern-library.md example matches correctly
    test_known_secrets.py       # every synthetic secret in corpus/known-secrets/ detected
    test_benign.py              # corpus/benign/ produces zero or minimal findings
    test_adversarial.py         # edge cases, near-misses, boundary conditions
    test_parity.py              # cross-engine comparison with allowlist

  reports/
    corpus_report.py            # per-pattern false positive/negative rates
    confidence_analysis.py      # confidence distribution stats per pattern
    parity_report.py            # detailed cross-engine divergence report
    format_text.py              # human-readable formatter for any JSON report

  output/                       # gitignored, report JSON files land here
```

## Engine Wrapper

`lib/engine_wrapper.py` provides a single interface to both engines.

```python
class EngineResult:
    """Normalized finding from either engine."""
    type: str              # pattern ID, e.g. "aws_access_key"
    confidence: float
    severity: str
    span: tuple[int, int]
    value_preview: str
    is_test_value: bool

class EngineWrapper:
    def __init__(self, engine: Literal["api", "standalone"]):
        # "api" imports from classifinder/app/engine/
        # "standalone" imports from classifinder-engine/

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EngineResult]:
        # normalize output into EngineResult regardless of source
```

Both engines have the same `scan()` function but return slightly different dataclass shapes. The wrapper normalizes them so all downstream code doesn't care which engine it's talking to.

## Cross-Engine Parity

`lib/comparator.py` runs the same input through both wrappers and diffs results:
- Same findings detected (by type and span)
- Same confidence scores (within tolerance of 0.01)
- Same severity classifications

`lib/parity_allowlist.py` is a dict mapping pattern IDs to reason strings:

```python
ALLOWED_DIVERGENCES = {
    # "pattern_id": "reason for temporary divergence"
}
```

Divergences involving allowlisted patterns are logged but don't fail `test_parity.py`. `reports/parity_report.py` produces the full detail.

## Pattern Library Validation

`lib/pattern_library_parser.py` parses `classifinder/docs/pattern-library.md` and extracts per pattern:
- Pattern ID (e.g., `aws_access_key`)
- Example string(s)
- Documented regex
- Category

`tests/test_pattern_library.py` is parametrized by pattern (50 test cases). For each pattern it:

1. Scans the example string through both engines
2. Asserts the correct pattern ID matched (not just "something matched")
3. Asserts confidence >= pattern's base confidence minus 0.05 (allows for entropy penalty on synthetic examples, but not wild underperformance)
4. Asserts severity matches the documented severity
5. Asserts the regex in pattern-library.md matches the compiled regex in the engine registry — catches doc drift

Failure output pinpoints exactly which pattern broke:
```
PASSED test_pattern_library[aws_access_key]
FAILED test_pattern_library[cohere_api_key] - confidence 0.42, expected >= 0.55
```

## JSON Output Schema

All tests and reports produce data conforming to these Pydantic models. This is the contract for a future UI.

```python
class PatternResult(BaseModel):
    pattern_id: str
    pattern_name: str
    category: str
    severity: str

class FindingResult(BaseModel):
    pattern: PatternResult
    confidence: float
    span: tuple[int, int]
    value_preview: str
    is_test_value: bool
    engine: Literal["api", "standalone"]

class CorpusFileResult(BaseModel):
    file_path: str
    corpus_type: Literal["benign", "known-secrets", "adversarial"]
    expected_findings: int
    actual_findings: list[FindingResult]
    false_positives: int
    false_negatives: int

class PatternStats(BaseModel):
    pattern_id: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float              # TP / (TP + FP)
    recall: float                 # TP / (TP + FN)
    confidence_mean: float
    confidence_median: float
    confidence_stddev: float
    entropy_penalty_count: int

class ParityDivergence(BaseModel):
    input_text_hash: str          # SHA-256 of input, not the text itself
    pattern_id: str
    field: str                    # "confidence", "severity", "missing"
    api_value: str | None
    standalone_value: str | None
    allowed: bool
    reason: str | None

class TestReport(BaseModel):
    """Top-level report — every output conforms to this."""
    report_type: Literal["pattern_validation", "corpus", "confidence", "parity"]
    timestamp: str                # ISO 8601
    engine_versions: dict         # {"api": "...", "standalone": "..."}
    summary: dict                 # type-specific summary stats
    results: list                 # PatternStats | CorpusFileResult | ParityDivergence
```

Reports write `TestReport` JSON to `output/`. `reports/format_text.py` reads any report JSON and renders human-readable tables to stdout.

## Report Scripts

**`reports/corpus_report.py`** — Scans every file in `corpus/` through both engines. Benign files: every finding is a false positive. Known-secrets files: missing expected matches (declared in `# expect:` headers) are false negatives. Outputs per-pattern `PatternStats` with precision/recall.

**`reports/confidence_analysis.py`** — Collects confidence scores per pattern across the full corpus. Outputs distribution stats: mean, median, stddev, histogram buckets. Flags patterns with high variance, low mean, or frequent entropy penalties.

**`reports/parity_report.py`** — Runs every corpus file through both engines and diffs finding-by-finding. Outputs `ParityDivergence` entries with summary counts.

**`reports/format_text.py`** — Reads any `TestReport` JSON and renders human-readable tables. Not a test runner, just a formatter.

```bash
python reports/corpus_report.py                     # writes output/corpus_TIMESTAMP.json
python reports/confidence_analysis.py               # writes output/confidence_TIMESTAMP.json
python reports/format_text.py output/corpus_*.json  # pretty-prints to terminal
```

## Corpus File Conventions

Each file declares expected results in header comments:

**Known-secrets:**
```
# expect: aws_access_key
# expect: aws_secret_key
AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Benign:**
```
# expect: none
Here is a README explaining how to configure your AWS credentials...
```

**Adversarial (should not match):**
```
# expect: none
# description: truncated AWS key - too short
AKIAIOSFODNN7
```

**Adversarial (should match):**
```
# expect: aws_access_key
# description: AWS key embedded in JSON string
{"credentials": "AKIAI44QH8DHBEXAMPLE"}
```

The `# expect:` and `# description:` lines are parsed by `lib/` utilities. Everything else is corpus text.

## Dependencies & Configuration

**pyproject.toml:**
- `pytest`, `pydantic`
- API engine: editable install from `../classifinder`
- Standalone engine: editable install from `../classifinder-engine`

**pytest markers:**
- `@pytest.mark.parity` — cross-engine tests (skip if only one engine available)
- `@pytest.mark.slow` — full corpus scans

**Gitignore policy:**
- `output/` — always ignored
- `corpus/` — curated fixtures committed, large scraped files ignored
- `corpus/.gitignore` documents the policy

## Future: UI

The JSON schema in `lib/schema.py` is designed as the contract for a future test results UI. All reports produce `TestReport` JSON to `output/`. The UI would read from there. No changes to the test/report layer needed when the UI is built.
