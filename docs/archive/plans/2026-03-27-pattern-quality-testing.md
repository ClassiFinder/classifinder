# Pattern Quality Testing Framework — Implementation Plan

> **STATUS: COMPLETED** — Implemented 2026-03-28/29. Full testing framework in `classifinder-tests/` with corpus-based testing, cross-engine parity, baseline regression detection, 5 report generators, and 11 test files. This plan is archived for historical reference.

> ~~**For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.~~

**Goal:** Build `classifinder-tests/`, a standalone test project that validates all 50 scanner patterns against documented examples, synthetic corpus data, and cross-engine parity checks — producing both pytest CI gates and structured JSON reports for a future UI.

**Architecture:** Layered design with shared `lib/` (engine wrappers, JSON schema, parsers), `tests/` (pytest CI gates), `reports/` (standalone analysis scripts), and `corpus/` (self-documenting test data). All output conforms to Pydantic models in `lib/schema.py` for future UI consumption.

**Tech Stack:** Python 3.12+, pytest, Pydantic v2

**Design spec:** `classifinder/docs/superpowers/specs/2026-03-27-pattern-quality-testing-design.md`

---

### Task 1: Scaffold Project Structure

**Files:**
- Create: `classifinder-tests/pyproject.toml`
- Create: `classifinder-tests/lib/__init__.py`
- Create: `classifinder-tests/tests/__init__.py`
- Create: `classifinder-tests/tests/conftest.py`
- Create: `classifinder-tests/reports/.gitkeep`
- Create: `classifinder-tests/output/.gitkeep`
- Create: `classifinder-tests/.gitignore`
- Create: `classifinder-tests/corpus/README.md`
- Create: `classifinder-tests/corpus/.gitignore`

- [ ] **Step 1: Create directory structure**

```bash
cd /Users/thomasparas/Documents/ClassiFinder
mkdir -p classifinder-tests/{lib,tests,reports,output}
mkdir -p classifinder-tests/corpus/{benign/{prose,code,config-templates,encoded},known-secrets/{cloud,payment,vcs,comms,database,ai,generic},adversarial}
```

- [ ] **Step 2: Create pyproject.toml**

```toml
# classifinder-tests/pyproject.toml
[project]
name = "classifinder-tests"
version = "0.1.0"
description = "Pattern quality testing framework for ClassiFinder"
requires-python = ">=3.12"
dependencies = [
    "pytest>=8.0.0",
    "pydantic>=2.0.0",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "parity: cross-engine parity tests (may skip if engine unavailable)",
    "slow: full corpus scans (deselect with -m 'not slow')",
]
```

- [ ] **Step 3: Create .gitignore**

```gitignore
# classifinder-tests/.gitignore
output/
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
```

- [ ] **Step 4: Create corpus/.gitignore**

```gitignore
# classifinder-tests/corpus/.gitignore
# Large scraped files are ignored — only curated fixtures are committed.
# To add a large corpus file, place it here and it won't be tracked.
# Hand-picked test fixtures should be committed normally.
benign/code/scraped/
benign/prose/scraped/
```

- [ ] **Step 5: Create corpus/README.md**

```markdown
# Test Corpus

## Structure

- `benign/` — text that should NOT trigger findings
  - `prose/` — articles, blog posts, plain English
  - `code/` — open-source code without real secrets
  - `config-templates/` — .env.example, docker-compose templates
  - `encoded/` — base64, public JWTs, non-secret high-entropy strings
- `known-secrets/` — synthetic strings that SHOULD trigger findings
  - Subdirs match engine pattern categories: cloud, payment, vcs, comms, database, ai, generic
- `adversarial/` — edge cases, near-misses, boundary conditions

## File Convention

Every corpus file declares expected results in header comments:

    # expect: aws_access_key
    # expect: aws_secret_key
    (corpus text here)

    # expect: none
    (benign text here)

    # expect: none
    # description: truncated key - should not match
    (adversarial text here)

## Adding Files

- Curated fixtures: commit directly
- Large scraped files: place in `benign/code/scraped/` or `benign/prose/scraped/` (gitignored)
- Synthetic secrets only in `known-secrets/` — never real credentials, even revoked
```

- [ ] **Step 6: Create empty __init__.py files**

```python
# classifinder-tests/lib/__init__.py
```

```python
# classifinder-tests/tests/__init__.py
```

- [ ] **Step 7: Create placeholder conftest.py**

```python
# classifinder-tests/tests/conftest.py
"""Shared pytest fixtures for classifinder-tests."""
```

- [ ] **Step 8: Create .gitkeep files for empty dirs**

```bash
touch classifinder-tests/reports/.gitkeep
touch classifinder-tests/output/.gitkeep
```

- [ ] **Step 9: Verify structure and run pytest (should collect 0 tests)**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && python -m pytest tests/ -v`
Expected: `collected 0 items` / `no tests ran`

- [ ] **Step 10: Commit**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests
git init
git add -A
git commit -m "chore: scaffold classifinder-tests project structure"
```

---

### Task 2: JSON Output Schema

**Files:**
- Create: `classifinder-tests/lib/schema.py`
- Create: `classifinder-tests/tests/test_schema.py`

- [ ] **Step 1: Write failing test for schema models**

```python
# classifinder-tests/tests/test_schema.py
"""Tests for JSON output schema models."""

from lib.schema import (
    PatternResult,
    FindingResult,
    CorpusFileResult,
    PatternStats,
    ParityDivergence,
    TestReport,
)


def test_pattern_result_creation():
    pr = PatternResult(
        pattern_id="aws_access_key",
        pattern_name="AWS Access Key ID",
        category="cloud",
        severity="critical",
    )
    assert pr.pattern_id == "aws_access_key"
    assert pr.severity == "critical"


def test_finding_result_creation():
    pr = PatternResult(
        pattern_id="aws_access_key",
        pattern_name="AWS Access Key ID",
        category="cloud",
        severity="critical",
    )
    fr = FindingResult(
        pattern=pr,
        confidence=0.95,
        span=(0, 20),
        value_preview="AKIA****MPLE",
        is_test_value=True,
        engine="api",
    )
    assert fr.confidence == 0.95
    assert fr.engine == "api"


def test_corpus_file_result_creation():
    cfr = CorpusFileResult(
        file_path="corpus/benign/prose/readme.txt",
        corpus_type="benign",
        expected_findings=0,
        actual_findings=[],
        false_positives=0,
        false_negatives=0,
    )
    assert cfr.corpus_type == "benign"
    assert cfr.false_positives == 0


def test_pattern_stats_creation():
    ps = PatternStats(
        pattern_id="aws_access_key",
        true_positives=10,
        false_positives=2,
        false_negatives=1,
        precision=0.833,
        recall=0.909,
        confidence_mean=0.92,
        confidence_median=0.95,
        confidence_stddev=0.05,
        entropy_penalty_count=0,
    )
    assert ps.precision == 0.833
    assert ps.recall == 0.909


def test_parity_divergence_creation():
    pd = ParityDivergence(
        input_text_hash="abc123",
        pattern_id="aws_access_key",
        field="confidence",
        api_value="0.95",
        standalone_value="0.93",
        allowed=False,
        reason=None,
    )
    assert pd.allowed is False


def test_test_report_creation():
    report = TestReport(
        report_type="pattern_validation",
        timestamp="2026-03-27T12:00:00Z",
        engine_versions={"api": "1.0.0", "standalone": "1.0.0"},
        summary={"total_patterns": 50, "passed": 48, "failed": 2},
        results=[],
    )
    assert report.report_type == "pattern_validation"


def test_test_report_json_round_trip():
    report = TestReport(
        report_type="corpus",
        timestamp="2026-03-27T12:00:00Z",
        engine_versions={"api": "1.0.0", "standalone": "1.0.0"},
        summary={"files_scanned": 10},
        results=[],
    )
    json_str = report.model_dump_json()
    restored = TestReport.model_validate_json(json_str)
    assert restored.report_type == "corpus"
    assert restored.summary == {"files_scanned": 10}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && python -m pytest tests/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lib.schema'`

- [ ] **Step 3: Write schema implementation**

```python
# classifinder-tests/lib/schema.py
"""JSON output schema for all test reports.

Every test result and report produces data conforming to these models.
This is the contract for a future UI — all report scripts write TestReport
JSON to output/, and any consumer reads from there.
"""

from __future__ import annotations

from typing import Literal, Any

from pydantic import BaseModel


class PatternResult(BaseModel):
    """Identifies a pattern involved in a finding or stat."""
    pattern_id: str
    pattern_name: str
    category: str
    severity: str


class FindingResult(BaseModel):
    """A single finding from scanning corpus text."""
    pattern: PatternResult
    confidence: float
    span: tuple[int, int]
    value_preview: str
    is_test_value: bool
    engine: Literal["api", "standalone"]


class CorpusFileResult(BaseModel):
    """Results from scanning one corpus file."""
    file_path: str
    corpus_type: Literal["benign", "known-secrets", "adversarial"]
    expected_findings: int
    actual_findings: list[FindingResult]
    false_positives: int
    false_negatives: int


class PatternStats(BaseModel):
    """Aggregate statistics for one pattern across a corpus."""
    pattern_id: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    confidence_mean: float
    confidence_median: float
    confidence_stddev: float
    entropy_penalty_count: int


class ParityDivergence(BaseModel):
    """A single difference between API and standalone engine results."""
    input_text_hash: str
    pattern_id: str
    field: str
    api_value: str | None
    standalone_value: str | None
    allowed: bool
    reason: str | None


class TestReport(BaseModel):
    """Top-level report — every output conforms to this."""
    report_type: Literal["pattern_validation", "corpus", "confidence", "parity"]
    timestamp: str
    engine_versions: dict[str, str]
    summary: dict[str, Any]
    results: list[Any]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_schema.py -v`
Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add lib/schema.py tests/test_schema.py
git commit -m "feat: add JSON output schema models"
```

---

### Task 3: Engine Wrapper

**Files:**
- Create: `classifinder-tests/lib/engine_wrapper.py`
- Create: `classifinder-tests/tests/test_engine_wrapper.py`

**Reference:**
- API engine: `classifinder/app/engine/scanner.py` — `scan(text, types, min_confidence, include_context) -> List[Finding]`
- Standalone engine: `classifinder-engine/scanner.py` — same signature and `Finding` dataclass
- Both `Finding` dataclasses have: `id`, `type`, `type_name`, `provider`, `severity`, `confidence`, `value_preview`, `span_start`, `span_end`, `context`, `is_likely_test_value`, `recommendation`, `matched_pattern`

- [ ] **Step 1: Write failing test for engine wrapper**

```python
# classifinder-tests/tests/test_engine_wrapper.py
"""Tests for the engine wrapper."""

import pytest
from lib.engine_wrapper import EngineWrapper, EngineResult


def test_api_engine_scans_aws_key():
    wrapper = EngineWrapper("api")
    results = wrapper.scan("AKIAIOSFODNN7EXAMPLE")
    assert len(results) >= 1
    aws_results = [r for r in results if r.type == "aws_access_key"]
    assert len(aws_results) == 1
    assert isinstance(aws_results[0], EngineResult)
    assert aws_results[0].severity == "critical"
    assert aws_results[0].span == (0, 20)


def test_standalone_engine_scans_aws_key():
    wrapper = EngineWrapper("standalone")
    results = wrapper.scan("AKIAIOSFODNN7EXAMPLE")
    assert len(results) >= 1
    aws_results = [r for r in results if r.type == "aws_access_key"]
    assert len(aws_results) == 1
    assert isinstance(aws_results[0], EngineResult)


def test_engine_wrapper_returns_engine_result():
    wrapper = EngineWrapper("api")
    results = wrapper.scan("sk_live_51H3aKLkdsjfhDKJSH38djfhksd")
    assert len(results) >= 1
    r = results[0]
    assert hasattr(r, "type")
    assert hasattr(r, "confidence")
    assert hasattr(r, "severity")
    assert hasattr(r, "span")
    assert hasattr(r, "value_preview")
    assert hasattr(r, "is_test_value")


def test_engine_wrapper_min_confidence():
    wrapper = EngineWrapper("api")
    all_results = wrapper.scan("AKIAIOSFODNN7EXAMPLE", min_confidence=0.0)
    high_results = wrapper.scan("AKIAIOSFODNN7EXAMPLE", min_confidence=0.9)
    # AKIAIOSFODNN7EXAMPLE is a known test value -> confidence 0.15
    # With min_confidence=0.9, it should be filtered out
    assert len(all_results) >= len(high_results)


def test_engine_wrapper_empty_text():
    wrapper = EngineWrapper("api")
    results = wrapper.scan("")
    assert results == []


def test_invalid_engine_type():
    with pytest.raises(ValueError, match="Unknown engine"):
        EngineWrapper("invalid")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_engine_wrapper.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lib.engine_wrapper'`

- [ ] **Step 3: Write engine wrapper implementation**

```python
# classifinder-tests/lib/engine_wrapper.py
"""Unified interface to both ClassiFinder scanner engines.

Abstracts over the API server engine (classifinder/app/engine/) and the
standalone open-source engine (classifinder-engine/) so all downstream
code — tests and reports — doesn't care which engine it's talking to.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Monorepo root — classifinder-tests/ is one level down
_MONOREPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class EngineResult:
    """Normalized finding from either engine."""
    type: str
    confidence: float
    severity: str
    span: tuple[int, int]
    value_preview: str
    is_test_value: bool


class EngineWrapper:
    """Wraps either scanner engine behind a common interface.

    Args:
        engine: Which engine to use — "api" for the API server's engine
                (classifinder/app/engine/), "standalone" for the open-source
                engine (classifinder-engine/).
    """

    def __init__(self, engine: Literal["api", "standalone"]) -> None:
        if engine not in ("api", "standalone"):
            raise ValueError(f"Unknown engine: {engine!r}. Use 'api' or 'standalone'.")
        self._engine = engine
        self._scan_fn = self._load_scan_fn()

    def _load_scan_fn(self):
        if self._engine == "api":
            api_path = str(_MONOREPO_ROOT / "classifinder")
            if api_path not in sys.path:
                sys.path.insert(0, api_path)
            from app.engine.scanner import scan
            return scan
        else:
            standalone_path = str(_MONOREPO_ROOT / "classifinder-engine")
            if standalone_path not in sys.path:
                sys.path.insert(0, standalone_path)
            from scanner import scan
            return scan

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EngineResult]:
        """Scan text and return normalized results.

        Args:
            text: The text to scan for secrets.
            min_confidence: Minimum confidence threshold (default 0.0 to get everything).

        Returns:
            List of EngineResult, sorted by span position.
        """
        findings = self._scan_fn(text, min_confidence=min_confidence)
        return [
            EngineResult(
                type=f.type,
                confidence=f.confidence,
                severity=f.severity,
                span=(f.span_start, f.span_end),
                value_preview=f.value_preview,
                is_test_value=f.is_likely_test_value,
            )
            for f in findings
        ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_engine_wrapper.py -v`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add lib/engine_wrapper.py tests/test_engine_wrapper.py
git commit -m "feat: add engine wrapper with unified scan interface"
```

---

### Task 4: Pattern Library Parser

**Files:**
- Create: `classifinder-tests/lib/pattern_library_parser.py`
- Create: `classifinder-tests/tests/test_pattern_library_parser.py`

**Reference:** `classifinder/docs/pattern-library.md` — each pattern has this markdown structure:
```
### N. `pattern_id` — Pattern Name
(description paragraph)
**Example:** `example_string`
**Regex:** `regex_string`
```

- [ ] **Step 1: Write failing test for parser**

```python
# classifinder-tests/tests/test_pattern_library_parser.py
"""Tests for the pattern library markdown parser."""

from lib.pattern_library_parser import parse_pattern_library, PatternEntry


def test_parse_returns_50_patterns():
    patterns = parse_pattern_library()
    assert len(patterns) == 50


def test_parse_returns_pattern_entry_objects():
    patterns = parse_pattern_library()
    assert all(isinstance(p, PatternEntry) for p in patterns)


def test_first_pattern_is_aws_access_key():
    patterns = parse_pattern_library()
    first = patterns[0]
    assert first.pattern_id == "aws_access_key"
    assert first.pattern_name == "AWS Access Key ID"
    assert first.category == "Cloud Providers"
    assert first.example == "AKIAIOSFODNN7EXAMPLE"
    assert "AKIA|ASIA" in first.regex


def test_last_pattern_is_generic_high_entropy():
    patterns = parse_pattern_library()
    last = patterns[-1]
    assert last.pattern_id == "generic_high_entropy"


def test_all_patterns_have_required_fields():
    patterns = parse_pattern_library()
    for p in patterns:
        assert p.pattern_id, f"Missing pattern_id: {p}"
        assert p.pattern_name, f"Missing pattern_name: {p}"
        assert p.category, f"Missing category: {p}"
        assert p.example, f"Missing example: {p}"
        assert p.regex, f"Missing regex: {p}"


def test_stripe_live_secret_key():
    patterns = parse_pattern_library()
    stripe = [p for p in patterns if p.pattern_id == "stripe_live_secret_key"]
    assert len(stripe) == 1
    assert stripe[0].example == "sk_live_51H3aKLkdsjfhDKJSH38djfhksd"
    assert stripe[0].category == "Payment & Financial"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_pattern_library_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write parser implementation**

```python
# classifinder-tests/lib/pattern_library_parser.py
"""Parse classifinder/docs/pattern-library.md into structured data.

Extracts pattern ID, name, category, example string, and regex for each
of the 50 patterns. This is the source of truth for pattern validation tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_MONOREPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PATTERN_LIBRARY_PATH = _MONOREPO_ROOT / "classifinder" / "docs" / "pattern-library.md"

# Matches: ### N. `pattern_id` — Pattern Name
_HEADER_RE = re.compile(r"^###\s+\d+\.\s+`([^`]+)`\s+[—–-]\s+(.+)$")

# Matches: **Example:** `example_string`
_EXAMPLE_RE = re.compile(r"^\*\*Example:\*\*\s+`([^`]+)`")

# Matches: **Regex:** `regex_string`
_REGEX_RE = re.compile(r"^\*\*Regex:\*\*\s+`(.+)`")

# Matches: ## Category Name (N patterns)
_CATEGORY_RE = re.compile(r"^##\s+(.+?)\s+\(\d+\s+patterns?\)")


@dataclass
class PatternEntry:
    """One parsed pattern from pattern-library.md."""
    pattern_id: str
    pattern_name: str
    category: str
    example: str
    regex: str


def parse_pattern_library(path: Path | None = None) -> list[PatternEntry]:
    """Parse pattern-library.md and return a list of PatternEntry objects.

    Args:
        path: Override path to the markdown file. Defaults to the standard
              location in the monorepo.

    Returns:
        List of 50 PatternEntry objects in document order.
    """
    md_path = path or _PATTERN_LIBRARY_PATH
    text = md_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    patterns: list[PatternEntry] = []
    current_category = ""
    current_id = ""
    current_name = ""
    current_example = ""
    current_regex = ""

    for line in lines:
        # Track current category
        cat_match = _CATEGORY_RE.match(line)
        if cat_match:
            current_category = cat_match.group(1)
            continue

        # Pattern header
        header_match = _HEADER_RE.match(line)
        if header_match:
            # Save previous pattern if we have one
            if current_id and current_example and current_regex:
                patterns.append(PatternEntry(
                    pattern_id=current_id,
                    pattern_name=current_name,
                    category=current_category,
                    example=current_example,
                    regex=current_regex,
                ))
            current_id = header_match.group(1)
            current_name = header_match.group(2)
            current_example = ""
            current_regex = ""
            continue

        # Example line
        example_match = _EXAMPLE_RE.match(line)
        if example_match:
            current_example = example_match.group(1)
            continue

        # Regex line
        regex_match = _REGEX_RE.match(line)
        if regex_match:
            current_regex = regex_match.group(1)
            continue

    # Don't forget the last pattern
    if current_id and current_example and current_regex:
        patterns.append(PatternEntry(
            pattern_id=current_id,
            pattern_name=current_name,
            category=current_category,
            example=current_example,
            regex=current_regex,
        ))

    return patterns
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_pattern_library_parser.py -v`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add lib/pattern_library_parser.py tests/test_pattern_library_parser.py
git commit -m "feat: add pattern library markdown parser"
```

---

### Task 5: Parity Allowlist & Comparator

**Files:**
- Create: `classifinder-tests/lib/parity_allowlist.py`
- Create: `classifinder-tests/lib/comparator.py`
- Create: `classifinder-tests/tests/test_comparator.py`

- [ ] **Step 1: Write failing test for comparator**

```python
# classifinder-tests/tests/test_comparator.py
"""Tests for the cross-engine parity comparator."""

from lib.engine_wrapper import EngineResult
from lib.comparator import compare_results, Divergence
from lib.parity_allowlist import ALLOWED_DIVERGENCES


def test_identical_results_produce_no_divergences():
    results_a = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=True),
    ]
    results_b = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=True),
    ]
    divergences = compare_results(results_a, results_b)
    assert divergences == []


def test_confidence_difference_produces_divergence():
    results_a = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    results_b = [
        EngineResult(type="aws_access_key", confidence=0.85, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    divergences = compare_results(results_a, results_b)
    assert len(divergences) == 1
    assert divergences[0].field == "confidence"
    assert divergences[0].api_value == "0.95"
    assert divergences[0].standalone_value == "0.85"


def test_confidence_within_tolerance_no_divergence():
    results_a = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    results_b = [
        EngineResult(type="aws_access_key", confidence=0.9501, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    divergences = compare_results(results_a, results_b)
    assert divergences == []


def test_missing_finding_produces_divergence():
    results_a = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    results_b = []
    divergences = compare_results(results_a, results_b)
    assert len(divergences) == 1
    assert divergences[0].field == "missing"
    assert divergences[0].standalone_value is None


def test_severity_difference_produces_divergence():
    results_a = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="critical",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    results_b = [
        EngineResult(type="aws_access_key", confidence=0.95, severity="high",
                     span=(0, 20), value_preview="AKIA****MPLE", is_test_value=False),
    ]
    divergences = compare_results(results_a, results_b)
    assert len(divergences) == 1
    assert divergences[0].field == "severity"


def test_allowlisted_divergence_marked_allowed():
    # Temporarily add an allowlist entry for this test
    ALLOWED_DIVERGENCES["test_pattern"] = "testing allowlist"
    try:
        results_a = [
            EngineResult(type="test_pattern", confidence=0.95, severity="critical",
                         span=(0, 20), value_preview="test****test", is_test_value=False),
        ]
        results_b = [
            EngineResult(type="test_pattern", confidence=0.80, severity="critical",
                         span=(0, 20), value_preview="test****test", is_test_value=False),
        ]
        divergences = compare_results(results_a, results_b)
        assert len(divergences) == 1
        assert divergences[0].allowed is True
        assert divergences[0].reason == "testing allowlist"
    finally:
        del ALLOWED_DIVERGENCES["test_pattern"]


def test_empty_results_no_divergences():
    divergences = compare_results([], [])
    assert divergences == []


def test_allowlist_starts_empty():
    assert ALLOWED_DIVERGENCES == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_comparator.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write parity allowlist**

```python
# classifinder-tests/lib/parity_allowlist.py
"""Known intentional divergences between API and standalone engines.

Add pattern IDs here when you've intentionally updated one engine but
haven't synced the other yet. Divergences involving allowlisted patterns
are logged but don't fail test_parity.py.

Format:
    ALLOWED_DIVERGENCES = {
        "pattern_id": "reason for temporary divergence",
    }
"""

ALLOWED_DIVERGENCES: dict[str, str] = {}
```

- [ ] **Step 4: Write comparator implementation**

```python
# classifinder-tests/lib/comparator.py
"""Cross-engine parity comparison.

Compares findings from the API engine and standalone engine on the same input.
Produces Divergence objects for any differences in type, confidence, or severity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .engine_wrapper import EngineResult
from .parity_allowlist import ALLOWED_DIVERGENCES

_CONFIDENCE_TOLERANCE = 0.01


@dataclass
class Divergence:
    """A single difference between two engine results."""
    pattern_id: str
    field: str  # "confidence", "severity", "missing"
    api_value: str | None
    standalone_value: str | None
    allowed: bool
    reason: str | None


def _check_allowed(pattern_id: str) -> tuple[bool, str | None]:
    if pattern_id in ALLOWED_DIVERGENCES:
        return True, ALLOWED_DIVERGENCES[pattern_id]
    return False, None


def compare_results(
    api_results: list[EngineResult],
    standalone_results: list[EngineResult],
) -> list[Divergence]:
    """Compare findings from both engines and return divergences.

    Matches findings by (type, span). Checks confidence (within tolerance)
    and severity for matched pairs. Reports missing findings in either direction.

    Args:
        api_results: Findings from the API engine.
        standalone_results: Findings from the standalone engine.

    Returns:
        List of Divergence objects. Empty list means perfect parity.
    """
    divergences: list[Divergence] = []

    # Index by (type, span) for matching
    api_by_key = {(r.type, r.span): r for r in api_results}
    standalone_by_key = {(r.type, r.span): r for r in standalone_results}

    all_keys = set(api_by_key.keys()) | set(standalone_by_key.keys())

    for key in sorted(all_keys):
        pattern_id = key[0]
        api_finding = api_by_key.get(key)
        standalone_finding = standalone_by_key.get(key)
        allowed, reason = _check_allowed(pattern_id)

        # Missing in one engine
        if api_finding and not standalone_finding:
            divergences.append(Divergence(
                pattern_id=pattern_id,
                field="missing",
                api_value=f"found at {key[1]}",
                standalone_value=None,
                allowed=allowed,
                reason=reason,
            ))
            continue

        if standalone_finding and not api_finding:
            divergences.append(Divergence(
                pattern_id=pattern_id,
                field="missing",
                api_value=None,
                standalone_value=f"found at {key[1]}",
                allowed=allowed,
                reason=reason,
            ))
            continue

        # Both present — check confidence
        if abs(api_finding.confidence - standalone_finding.confidence) > _CONFIDENCE_TOLERANCE:
            divergences.append(Divergence(
                pattern_id=pattern_id,
                field="confidence",
                api_value=str(api_finding.confidence),
                standalone_value=str(standalone_finding.confidence),
                allowed=allowed,
                reason=reason,
            ))

        # Check severity
        if api_finding.severity != standalone_finding.severity:
            divergences.append(Divergence(
                pattern_id=pattern_id,
                field="severity",
                api_value=api_finding.severity,
                standalone_value=standalone_finding.severity,
                allowed=allowed,
                reason=reason,
            ))

    return divergences
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_comparator.py -v`
Expected: 8 tests PASS

- [ ] **Step 6: Commit**

```bash
git add lib/parity_allowlist.py lib/comparator.py tests/test_comparator.py
git commit -m "feat: add cross-engine parity comparator with allowlist"
```

---

### Task 6: Corpus File Parser

**Files:**
- Create: `classifinder-tests/lib/corpus_parser.py`
- Create: `classifinder-tests/tests/test_corpus_parser.py`

- [ ] **Step 1: Write failing test for corpus parser**

```python
# classifinder-tests/tests/test_corpus_parser.py
"""Tests for corpus file header parser."""

from lib.corpus_parser import parse_corpus_file, CorpusExpectation


def test_parse_known_secret_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("# expect: aws_access_key\n# expect: aws_secret_key\nAKIAIOSFODNN7EXAMPLE\n")
    result = parse_corpus_file(f)
    assert result.expected_types == ["aws_access_key", "aws_secret_key"]
    assert result.expect_none is False
    assert result.description is None
    assert "AKIAIOSFODNN7EXAMPLE" in result.text


def test_parse_benign_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("# expect: none\nJust some normal text here.\n")
    result = parse_corpus_file(f)
    assert result.expected_types == []
    assert result.expect_none is True
    assert "Just some normal text" in result.text


def test_parse_adversarial_file_with_description(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("# expect: none\n# description: truncated key\nAKIAIOSFODNN7\n")
    result = parse_corpus_file(f)
    assert result.expect_none is True
    assert result.description == "truncated key"


def test_parse_strips_header_from_text(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("# expect: aws_access_key\n# description: test\nthe actual text\n")
    result = parse_corpus_file(f)
    assert result.text == "the actual text\n"
    assert "# expect" not in result.text
    assert "# description" not in result.text


def test_parse_file_with_no_headers(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("just raw text with no headers\n")
    result = parse_corpus_file(f)
    assert result.expected_types == []
    assert result.expect_none is False
    assert result.description is None
    assert result.text == "just raw text with no headers\n"


def test_parse_multiple_expects(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text(
        "# expect: stripe_live_secret_key\n"
        "# expect: openai_api_key\n"
        "# expect: github_pat_classic\n"
        "sk_live_abc123 and sk-abc123 and ghp_abc123\n"
    )
    result = parse_corpus_file(f)
    assert result.expected_types == [
        "stripe_live_secret_key",
        "openai_api_key",
        "github_pat_classic",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_corpus_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write corpus parser implementation**

```python
# classifinder-tests/lib/corpus_parser.py
"""Parse corpus file headers to extract test expectations.

Each corpus file can declare expected results in header comments:
    # expect: pattern_id
    # expect: none
    # description: what this tests

The parser extracts these headers and returns the remaining text for scanning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_EXPECT_RE = re.compile(r"^#\s*expect:\s*(.+)$")
_DESCRIPTION_RE = re.compile(r"^#\s*description:\s*(.+)$")


@dataclass
class CorpusExpectation:
    """Parsed expectations from a corpus file."""
    expected_types: list[str] = field(default_factory=list)
    expect_none: bool = False
    description: str | None = None
    text: str = ""


def parse_corpus_file(path: Path) -> CorpusExpectation:
    """Parse a corpus file and extract header expectations.

    Args:
        path: Path to the corpus file.

    Returns:
        CorpusExpectation with parsed headers and the remaining text.
    """
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)

    expected_types: list[str] = []
    expect_none = False
    description: str | None = None
    text_lines: list[str] = []
    in_headers = True

    for line in lines:
        stripped = line.strip()

        if in_headers:
            expect_match = _EXPECT_RE.match(stripped)
            if expect_match:
                value = expect_match.group(1).strip()
                if value == "none":
                    expect_none = True
                else:
                    expected_types.append(value)
                continue

            desc_match = _DESCRIPTION_RE.match(stripped)
            if desc_match:
                description = desc_match.group(1).strip()
                continue

            # First non-header line — switch to text mode
            in_headers = False

        text_lines.append(line)

    return CorpusExpectation(
        expected_types=expected_types,
        expect_none=expect_none,
        description=description,
        text="".join(text_lines),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_corpus_parser.py -v`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add lib/corpus_parser.py tests/test_corpus_parser.py
git commit -m "feat: add corpus file header parser"
```

---

### Task 7: Conftest Fixtures

**Files:**
- Modify: `classifinder-tests/tests/conftest.py`

- [ ] **Step 1: Write shared fixtures**

```python
# classifinder-tests/tests/conftest.py
"""Shared pytest fixtures for classifinder-tests."""

import sys
from pathlib import Path

import pytest

# Ensure lib/ is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from lib.engine_wrapper import EngineWrapper
from lib.pattern_library_parser import parse_pattern_library, PatternEntry


@pytest.fixture(scope="session")
def api_engine() -> EngineWrapper:
    """API server engine wrapper (session-scoped for performance)."""
    return EngineWrapper("api")


@pytest.fixture(scope="session")
def standalone_engine() -> EngineWrapper:
    """Standalone engine wrapper (session-scoped for performance)."""
    return EngineWrapper("standalone")


@pytest.fixture(scope="session")
def pattern_library() -> list[PatternEntry]:
    """All 50 patterns parsed from pattern-library.md."""
    return parse_pattern_library()


@pytest.fixture(scope="session")
def pattern_library_by_id(pattern_library) -> dict[str, PatternEntry]:
    """Pattern library indexed by pattern_id for quick lookup."""
    return {p.pattern_id: p for p in pattern_library}


@pytest.fixture(scope="session")
def api_registry() -> dict:
    """The API engine's live pattern registry, indexed by pattern ID.

    Returns a dict of {pattern_id: SecretPattern} from the API engine's
    PATTERN_REGISTRY. Used for comparing documented regexes against actual.
    """
    _monorepo = Path(__file__).resolve().parent.parent.parent
    api_path = str(_monorepo / "classifinder")
    if api_path not in sys.path:
        sys.path.insert(0, api_path)
    from app.engine.patterns.registry import PATTERN_REGISTRY
    return {p.id: p for p in PATTERN_REGISTRY}
```

- [ ] **Step 2: Verify existing tests still pass with new conftest**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/ -v`
Expected: All previously passing tests still pass.

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "feat: add shared pytest fixtures for engines and pattern library"
```

---

### Task 8: Pattern Library Validation Tests (CI Gate)

**Files:**
- Create: `classifinder-tests/tests/test_pattern_library.py`

**Reference:** This is the core CI gate from the design spec. Every pattern-library.md example must:
1. Match the correct pattern ID
2. Meet base confidence minus 0.05 tolerance
3. Match documented severity
4. Have a regex that matches the actual engine registry regex

- [ ] **Step 1: Write the parametrized test**

```python
# classifinder-tests/tests/test_pattern_library.py
"""Pattern library validation — CI gate.

Every example in pattern-library.md must:
1. Be detected by the correct pattern ID (both engines)
2. Meet the pattern's base confidence minus 0.05 tolerance
3. Have the correct severity
4. Have a documented regex matching the actual compiled regex in the registry

Parametrized by pattern — each of the 50 patterns is a separate test case.
"""

import pytest
from lib.pattern_library_parser import PatternEntry


def _get_pattern_ids(pattern_library):
    return [p.pattern_id for p in pattern_library]


def _find_by_type(results, pattern_id):
    return [r for r in results if r.type == pattern_id]


class TestPatternLibraryAPIEngine:
    """Validate every pattern-library.md example against the API engine."""

    def test_example_detected_by_correct_pattern(
        self, api_engine, pattern_library, api_registry
    ):
        for entry in pattern_library:
            results = api_engine.scan(entry.example, min_confidence=0.0)
            matches = _find_by_type(results, entry.pattern_id)
            assert len(matches) >= 1, (
                f"Pattern '{entry.pattern_id}': example '{entry.example}' "
                f"not detected. Got types: {[r.type for r in results]}"
            )

    def test_example_confidence_meets_base(
        self, api_engine, pattern_library, api_registry
    ):
        for entry in pattern_library:
            registry_pattern = api_registry.get(entry.pattern_id)
            if not registry_pattern:
                pytest.skip(f"Pattern '{entry.pattern_id}' not in registry")
            results = api_engine.scan(entry.example, min_confidence=0.0)
            matches = _find_by_type(results, entry.pattern_id)
            if not matches:
                pytest.fail(
                    f"Pattern '{entry.pattern_id}': example not detected "
                    f"(can't check confidence)"
                )
            min_expected = registry_pattern.confidence_base - 0.05
            actual = matches[0].confidence
            assert actual >= min_expected, (
                f"Pattern '{entry.pattern_id}': confidence {actual} "
                f"below base {registry_pattern.confidence_base} - 0.05 = {min_expected}"
            )

    def test_example_severity_matches(
        self, api_engine, pattern_library, api_registry
    ):
        for entry in pattern_library:
            registry_pattern = api_registry.get(entry.pattern_id)
            if not registry_pattern:
                pytest.skip(f"Pattern '{entry.pattern_id}' not in registry")
            results = api_engine.scan(entry.example, min_confidence=0.0)
            matches = _find_by_type(results, entry.pattern_id)
            if not matches:
                pytest.fail(
                    f"Pattern '{entry.pattern_id}': example not detected "
                    f"(can't check severity)"
                )
            assert matches[0].severity == registry_pattern.severity, (
                f"Pattern '{entry.pattern_id}': severity '{matches[0].severity}' "
                f"!= registry '{registry_pattern.severity}'"
            )

    def test_documented_regex_matches_registry(
        self, pattern_library, api_registry
    ):
        for entry in pattern_library:
            registry_pattern = api_registry.get(entry.pattern_id)
            if not registry_pattern:
                pytest.fail(
                    f"Pattern '{entry.pattern_id}' in docs but not in engine registry"
                )
            # The registry regex includes named groups and flags that the
            # docs omit. Check that the documented regex appears as a
            # substring of the compiled pattern (the core logic portion).
            compiled_pattern = registry_pattern.regex.pattern
            # Normalize whitespace for comparison
            doc_regex = entry.regex.strip()
            assert doc_regex in compiled_pattern, (
                f"Pattern '{entry.pattern_id}': documented regex not found "
                f"in compiled pattern.\n"
                f"  Doc:      {doc_regex}\n"
                f"  Compiled: {compiled_pattern}"
            )


class TestPatternLibraryStandaloneEngine:
    """Validate every pattern-library.md example against the standalone engine."""

    @pytest.mark.parity
    def test_example_detected_by_correct_pattern(
        self, standalone_engine, pattern_library
    ):
        for entry in pattern_library:
            results = standalone_engine.scan(entry.example, min_confidence=0.0)
            matches = _find_by_type(results, entry.pattern_id)
            assert len(matches) >= 1, (
                f"Standalone — Pattern '{entry.pattern_id}': example "
                f"'{entry.example}' not detected. "
                f"Got types: {[r.type for r in results]}"
            )
```

- [ ] **Step 2: Run tests to verify they execute**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_pattern_library.py -v`
Expected: Tests execute. Some may fail if doc regexes don't exactly substring-match the compiled patterns — that's expected and reveals doc drift. Note which patterns fail for investigation.

- [ ] **Step 3: Investigate and fix any failures**

If regex comparison tests fail, examine the specific patterns where the documented regex doesn't match the compiled regex. Either the docs or the engine patterns need updating. Fix whichever is wrong. If neither is wrong but the comparison logic is too strict (e.g., the compiled regex wraps the documented regex in a named group), adjust the assertion in `test_documented_regex_matches_registry` to account for the `(?P<secret>...)` wrapper.

- [ ] **Step 4: Run tests again to verify all pass**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_pattern_library.py -v`
Expected: All tests PASS (or known failures documented)

- [ ] **Step 5: Commit**

```bash
git add tests/test_pattern_library.py
git commit -m "feat: add pattern library validation tests for all 50 patterns"
```

---

### Task 9: Cross-Engine Parity Tests (CI Gate)

**Files:**
- Create: `classifinder-tests/tests/test_parity.py`

- [ ] **Step 1: Write parity test**

```python
# classifinder-tests/tests/test_parity.py
"""Cross-engine parity tests — CI gate.

Runs every pattern-library.md example through both engines and fails on
any non-allowlisted divergence. Uses the comparator from lib/.
"""

import pytest
from lib.comparator import compare_results


@pytest.mark.parity
class TestCrossEngineParity:
    """Both engines must produce identical results on pattern-library.md examples."""

    def test_pattern_library_examples_match(
        self, api_engine, standalone_engine, pattern_library
    ):
        all_divergences = []
        for entry in pattern_library:
            api_results = api_engine.scan(entry.example, min_confidence=0.0)
            standalone_results = standalone_engine.scan(
                entry.example, min_confidence=0.0
            )
            divergences = compare_results(api_results, standalone_results)
            unallowed = [d for d in divergences if not d.allowed]
            for d in unallowed:
                all_divergences.append(
                    f"  {entry.pattern_id} ({entry.example[:30]}...): "
                    f"{d.field} — api={d.api_value}, standalone={d.standalone_value}"
                )

        assert all_divergences == [], (
            f"Cross-engine divergences found:\n"
            + "\n".join(all_divergences)
        )
```

- [ ] **Step 2: Run test**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_parity.py -v`
Expected: PASS if engines are in sync. If there are divergences, either fix the engine that's wrong or add entries to `lib/parity_allowlist.py` with reasons.

- [ ] **Step 3: Commit**

```bash
git add tests/test_parity.py
git commit -m "feat: add cross-engine parity CI gate"
```

---

### Task 10: Seed Known-Secrets Corpus

**Files:**
- Create: `classifinder-tests/corpus/known-secrets/cloud/aws.txt`
- Create: `classifinder-tests/corpus/known-secrets/cloud/gcp.txt`
- Create: `classifinder-tests/corpus/known-secrets/cloud/azure.txt`
- Create: `classifinder-tests/corpus/known-secrets/payment/stripe.txt`
- Create: `classifinder-tests/corpus/known-secrets/vcs/github.txt`
- Create: `classifinder-tests/corpus/known-secrets/comms/slack.txt`
- Create: `classifinder-tests/corpus/known-secrets/database/connection_strings.txt`
- Create: `classifinder-tests/corpus/known-secrets/ai/llm_providers.txt`
- Create: `classifinder-tests/corpus/known-secrets/generic/tokens.txt`

These contain synthetic secrets (structurally valid format, not real credentials) with `# expect:` headers. All examples taken from pattern-library.md plus additional synthetic variations.

- [ ] **Step 1: Create cloud provider corpus files**

```
# classifinder-tests/corpus/known-secrets/cloud/aws.txt
# expect: aws_access_key
AKIAIOSFODNN7EXAMPLE

# expect: aws_access_key
ASIAJEXAMPLEXEG2JICEA

# expect: aws_secret_key
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```
# classifinder-tests/corpus/known-secrets/cloud/gcp.txt
# expect: gcp_api_key
AIzaSyA-FAKE-KEY-FOR-TESTING-1234567
```

```
# classifinder-tests/corpus/known-secrets/cloud/azure.txt
# expect: azure_storage_key
AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==

# expect: azure_ad_client_secret
AZURE_CLIENT_SECRET=a1b2c3d4~e5f6.g7h8_i9j0k1l2m3n4o5p6q7
```

- [ ] **Step 2: Create payment corpus**

```
# classifinder-tests/corpus/known-secrets/payment/stripe.txt
# expect: stripe_live_secret_key
sk_live_51H3aKLkdsjfhDKJSH38djfhksd

# expect: stripe_test_secret_key
sk_test_4eC39HqLyjWDarjtT1zdp7dc

# expect: stripe_webhook_secret
whsec_1234abcd5678efgh9012ijkl
```

- [ ] **Step 3: Create VCS corpus**

```
# classifinder-tests/corpus/known-secrets/vcs/github.txt
# expect: github_pat_classic
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh

# expect: gitlab_pat
glpat-ABCDEFGHIJKLMNOPQRST
```

- [ ] **Step 4: Create comms corpus**

```
# classifinder-tests/corpus/known-secrets/comms/slack.txt
# expect: slack_bot_token
xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx

# expect: sendgrid_api_key
SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs
```

- [ ] **Step 5: Create database corpus**

```
# classifinder-tests/corpus/known-secrets/database/connection_strings.txt
# expect: postgres_connection_string
postgres://admin:s3cur3p4ss@db.internal:5432/production

# expect: mysql_connection_string
mysql+pymysql://root:password@localhost:3306/mydb

# expect: mongodb_connection_string
mongodb+srv://user:MyP4ssword@cluster0.abc123.mongodb.net/mydb

# expect: redis_connection_string
redis://:s3cretP4ss@redis.internal:6379/0
```

- [ ] **Step 6: Create AI provider corpus**

```
# classifinder-tests/corpus/known-secrets/ai/llm_providers.txt
# expect: openai_api_key
sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234

# expect: anthropic_api_key
sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901

# expect: cohere_api_key
COHERE_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

- [ ] **Step 7: Create generic tokens corpus**

```
# classifinder-tests/corpus/known-secrets/generic/tokens.txt
# expect: jwt_token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# expect: bearer_token
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789jkl012mno345pqr
```

- [ ] **Step 8: Commit**

```bash
git add corpus/known-secrets/
git commit -m "feat: seed known-secrets corpus with synthetic examples"
```

---

### Task 11: Seed Adversarial Corpus

**Files:**
- Create: `classifinder-tests/corpus/adversarial/truncated_keys.txt`
- Create: `classifinder-tests/corpus/adversarial/wrong_prefix.txt`
- Create: `classifinder-tests/corpus/adversarial/embedded_in_json.txt`
- Create: `classifinder-tests/corpus/adversarial/near_misses.txt`

- [ ] **Step 1: Create truncated key tests**

```
# classifinder-tests/corpus/adversarial/truncated_keys.txt
# expect: none
# description: AWS key with only 13 chars after prefix - too short
AKIAIOSFODNN7

# expect: none
# description: GitHub PAT with only 20 chars after prefix - too short
ghp_ABCDEFGHIJKLMNOPQRST

# expect: none
# description: Stripe key with only 10 chars after prefix - too short
sk_live_1234567890
```

- [ ] **Step 2: Create wrong prefix tests**

```
# classifinder-tests/corpus/adversarial/wrong_prefix.txt
# expect: none
# description: BKIA is not a valid AWS key prefix
BKIAIOSFODNN7EXAMPLE12

# expect: none
# description: sk_prod_ is not a valid Stripe prefix
sk_prod_51H3aKLkdsjfhDKJSH38djfhksd
```

- [ ] **Step 3: Create embedded-in-context tests**

```
# classifinder-tests/corpus/adversarial/embedded_in_json.txt
# expect: aws_access_key
# description: AWS key embedded in JSON value - should still match
{"aws_access_key_id": "AKIAI44QH8DHBEXAMPLE"}

# expect: stripe_live_secret_key
# description: Stripe key in a URL parameter - should still match
https://api.example.com/webhook?key=sk_live_51H3aKLkdsjfhDKJSH38djfhksd
```

- [ ] **Step 4: Create near-miss tests**

```
# classifinder-tests/corpus/adversarial/near_misses.txt
# expect: none
# description: AKIA as a word in prose, not a key
The AKIA protocol is used for authentication in legacy systems.

# expect: none
# description: lowercase letters after AKIA prefix - real keys are uppercase
akiaiosfodnn7example
```

- [ ] **Step 5: Commit**

```bash
git add corpus/adversarial/
git commit -m "feat: seed adversarial corpus with edge cases and near-misses"
```

---

### Task 12: Corpus-Based Pytest Tests (CI Gates)

**Files:**
- Create: `classifinder-tests/tests/test_known_secrets.py`
- Create: `classifinder-tests/tests/test_benign.py`
- Create: `classifinder-tests/tests/test_adversarial.py`

- [ ] **Step 1: Write known-secrets test**

```python
# classifinder-tests/tests/test_known_secrets.py
"""Known secrets corpus test — CI gate.

Every file in corpus/known-secrets/ declares expected pattern matches.
This test fails if any declared expected pattern is not detected.
"""

from pathlib import Path

import pytest

from lib.corpus_parser import parse_corpus_file

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus" / "known-secrets"


def _collect_corpus_files():
    """Collect all .txt files in the known-secrets corpus."""
    if not _CORPUS_DIR.exists():
        return []
    return sorted(_CORPUS_DIR.rglob("*.txt"))


@pytest.mark.parametrize("corpus_file", _collect_corpus_files(), ids=lambda p: str(p.relative_to(_CORPUS_DIR)))
def test_known_secret_detected(corpus_file, api_engine):
    expectation = parse_corpus_file(corpus_file)
    if not expectation.expected_types:
        pytest.skip("No expected types declared")

    results = api_engine.scan(expectation.text, min_confidence=0.0)
    detected_types = {r.type for r in results}

    for expected_type in expectation.expected_types:
        assert expected_type in detected_types, (
            f"File: {corpus_file.name}\n"
            f"Expected pattern '{expected_type}' not detected.\n"
            f"Detected: {detected_types}\n"
            f"Text: {expectation.text[:100]}..."
        )
```

- [ ] **Step 2: Write adversarial test**

```python
# classifinder-tests/tests/test_adversarial.py
"""Adversarial corpus test — CI gate.

Tests edge cases and boundary conditions from corpus/adversarial/.
Files with '# expect: none' must produce zero findings.
Files with '# expect: pattern_id' must detect that pattern.
"""

from pathlib import Path

import pytest

from lib.corpus_parser import parse_corpus_file

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus" / "adversarial"


def _collect_corpus_files():
    if not _CORPUS_DIR.exists():
        return []
    return sorted(_CORPUS_DIR.rglob("*.txt"))


@pytest.mark.parametrize("corpus_file", _collect_corpus_files(), ids=lambda p: p.stem)
def test_adversarial_case(corpus_file, api_engine):
    expectation = parse_corpus_file(corpus_file)

    # Each adversarial file may contain multiple test blocks separated by
    # blank lines. For now, scan the whole file as one text block.
    results = api_engine.scan(expectation.text, min_confidence=0.0)
    detected_types = {r.type for r in results}

    if expectation.expect_none:
        assert len(results) == 0, (
            f"File: {corpus_file.name} (expect: none)\n"
            f"Description: {expectation.description}\n"
            f"Unexpected findings: {detected_types}\n"
            f"Text: {expectation.text[:100]}..."
        )
    else:
        for expected_type in expectation.expected_types:
            assert expected_type in detected_types, (
                f"File: {corpus_file.name}\n"
                f"Description: {expectation.description}\n"
                f"Expected '{expected_type}' not detected.\n"
                f"Detected: {detected_types}"
            )
```

- [ ] **Step 3: Write benign test**

```python
# classifinder-tests/tests/test_benign.py
"""Benign corpus test — CI gate.

Every file in corpus/benign/ should produce zero findings (or very few).
Any finding in benign text is a false positive.
"""

from pathlib import Path

import pytest

from lib.corpus_parser import parse_corpus_file

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus" / "benign"


def _collect_corpus_files():
    if not _CORPUS_DIR.exists():
        return []
    return sorted(_CORPUS_DIR.rglob("*.txt"))


@pytest.mark.parametrize("corpus_file", _collect_corpus_files(), ids=lambda p: str(p.relative_to(_CORPUS_DIR)))
@pytest.mark.slow
def test_benign_produces_no_findings(corpus_file, api_engine):
    expectation = parse_corpus_file(corpus_file)
    results = api_engine.scan(expectation.text, min_confidence=0.3)
    assert len(results) == 0, (
        f"File: {corpus_file.name}\n"
        f"False positives detected: {[(r.type, r.confidence) for r in results]}\n"
        f"Text snippet: {expectation.text[:100]}..."
    )
```

- [ ] **Step 4: Run all corpus tests**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/test_known_secrets.py tests/test_adversarial.py tests/test_benign.py -v`
Expected: Known-secrets and adversarial tests mostly PASS. Benign tests skip if no corpus files exist yet. Note any failures for investigation.

- [ ] **Step 5: Commit**

```bash
git add tests/test_known_secrets.py tests/test_adversarial.py tests/test_benign.py
git commit -m "feat: add corpus-based pytest CI gates for known-secrets, adversarial, and benign"
```

---

### Task 13: Corpus Report Script

**Files:**
- Create: `classifinder-tests/reports/corpus_report.py`

- [ ] **Step 1: Write corpus report script**

```python
# classifinder-tests/reports/corpus_report.py
"""Scan the full corpus and produce per-pattern statistics.

Outputs a TestReport JSON to output/ with PatternStats for each pattern:
precision, recall, confidence distribution, false positive/negative counts.

Usage:
    cd classifinder-tests
    PYTHONPATH=. python reports/corpus_report.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, stdev

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from lib.engine_wrapper import EngineWrapper
from lib.corpus_parser import parse_corpus_file
from lib.schema import PatternStats, TestReport

_CORPUS_DIR = _PROJECT_ROOT / "corpus"
_OUTPUT_DIR = _PROJECT_ROOT / "output"


def _collect_all_corpus_files() -> list[Path]:
    return sorted(_CORPUS_DIR.rglob("*.txt"))


def run_corpus_report(engine_name: str = "api") -> TestReport:
    engine = EngineWrapper(engine_name)
    files = _collect_all_corpus_files()

    # Accumulators per pattern
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    confidences: dict[str, list[float]] = defaultdict(list)
    all_pattern_ids: set[str] = set()

    for corpus_file in files:
        expectation = parse_corpus_file(corpus_file)
        results = engine.scan(expectation.text, min_confidence=0.0)
        detected_types = {r.type for r in results}

        for r in results:
            confidences[r.type].append(r.confidence)
            all_pattern_ids.add(r.type)

        if expectation.expect_none:
            # Every finding is a false positive
            for r in results:
                fp[r.type] += 1
        else:
            # Check expected vs detected
            for expected_type in expectation.expected_types:
                all_pattern_ids.add(expected_type)
                if expected_type in detected_types:
                    tp[expected_type] += 1
                else:
                    fn[expected_type] += 1
            # Findings not in expected list are false positives
            expected_set = set(expectation.expected_types)
            for r in results:
                if r.type not in expected_set:
                    fp[r.type] += 1

    # Build PatternStats for each pattern seen
    stats: list[dict] = []
    for pid in sorted(all_pattern_ids):
        t = tp[pid]
        f_p = fp[pid]
        f_n = fn[pid]
        confs = confidences.get(pid, [])
        precision = t / (t + f_p) if (t + f_p) > 0 else 0.0
        recall = t / (t + f_n) if (t + f_n) > 0 else 0.0
        stats.append(PatternStats(
            pattern_id=pid,
            true_positives=t,
            false_positives=f_p,
            false_negatives=f_n,
            precision=round(precision, 3),
            recall=round(recall, 3),
            confidence_mean=round(mean(confs), 3) if confs else 0.0,
            confidence_median=round(median(confs), 3) if confs else 0.0,
            confidence_stddev=round(stdev(confs), 3) if len(confs) > 1 else 0.0,
            entropy_penalty_count=0,  # TODO: requires engine instrumentation
        ).model_dump())

    report = TestReport(
        report_type="corpus",
        timestamp=datetime.now(timezone.utc).isoformat(),
        engine_versions={engine_name: "1.0.0"},
        summary={
            "files_scanned": len(files),
            "patterns_seen": len(all_pattern_ids),
            "total_true_positives": sum(tp.values()),
            "total_false_positives": sum(fp.values()),
            "total_false_negatives": sum(fn.values()),
        },
        results=stats,
    )
    return report


def main():
    _OUTPUT_DIR.mkdir(exist_ok=True)
    report = run_corpus_report()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = _OUTPUT_DIR / f"corpus_{timestamp}.json"
    output_path.write_text(report.model_dump_json(indent=2))
    print(f"Report written to {output_path}")
    print(f"Files scanned: {report.summary['files_scanned']}")
    print(f"Patterns seen: {report.summary['patterns_seen']}")
    print(f"TP: {report.summary['total_true_positives']} | "
          f"FP: {report.summary['total_false_positives']} | "
          f"FN: {report.summary['total_false_negatives']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the report**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python reports/corpus_report.py`
Expected: Produces a JSON file in `output/` and prints summary to stdout.

- [ ] **Step 3: Commit**

```bash
git add reports/corpus_report.py
git commit -m "feat: add corpus report script with per-pattern statistics"
```

---

### Task 14: Confidence Analysis Report Script

**Files:**
- Create: `classifinder-tests/reports/confidence_analysis.py`

- [ ] **Step 1: Write confidence analysis script**

```python
# classifinder-tests/reports/confidence_analysis.py
"""Analyze confidence score distributions per pattern.

Scans the full corpus and collects confidence scores per pattern.
Flags patterns with concerning distributions: high variance, low mean,
frequent clustering near minimum confidence.

Usage:
    cd classifinder-tests
    PYTHONPATH=. python reports/confidence_analysis.py
"""

from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, stdev

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from lib.engine_wrapper import EngineWrapper
from lib.corpus_parser import parse_corpus_file
from lib.schema import TestReport

_CORPUS_DIR = _PROJECT_ROOT / "corpus"
_OUTPUT_DIR = _PROJECT_ROOT / "output"

# Thresholds for flagging patterns
_LOW_MEAN_THRESHOLD = 0.4
_HIGH_STDDEV_THRESHOLD = 0.2


def run_confidence_analysis(engine_name: str = "api") -> TestReport:
    engine = EngineWrapper(engine_name)
    files = sorted(_CORPUS_DIR.rglob("*.txt"))

    confidences: dict[str, list[float]] = defaultdict(list)

    for corpus_file in files:
        expectation = parse_corpus_file(corpus_file)
        results = engine.scan(expectation.text, min_confidence=0.0)
        for r in results:
            confidences[r.type].append(r.confidence)

    results_data: list[dict] = []
    flagged: list[str] = []

    for pid in sorted(confidences.keys()):
        confs = confidences[pid]
        conf_mean = round(mean(confs), 3) if confs else 0.0
        conf_median = round(median(confs), 3) if confs else 0.0
        conf_stddev = round(stdev(confs), 3) if len(confs) > 1 else 0.0
        low_count = sum(1 for c in confs if c <= 0.2)

        flags = []
        if conf_mean < _LOW_MEAN_THRESHOLD:
            flags.append("low_mean")
        if conf_stddev > _HIGH_STDDEV_THRESHOLD:
            flags.append("high_variance")
        if low_count > len(confs) * 0.5:
            flags.append("mostly_low_confidence")

        if flags:
            flagged.append(f"{pid}: {', '.join(flags)}")

        # Histogram buckets: 0.0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0
        histogram = {
            "0.0-0.2": sum(1 for c in confs if c < 0.2),
            "0.2-0.4": sum(1 for c in confs if 0.2 <= c < 0.4),
            "0.4-0.6": sum(1 for c in confs if 0.4 <= c < 0.6),
            "0.6-0.8": sum(1 for c in confs if 0.6 <= c < 0.8),
            "0.8-1.0": sum(1 for c in confs if 0.8 <= c <= 1.0),
        }

        results_data.append({
            "pattern_id": pid,
            "sample_count": len(confs),
            "confidence_mean": conf_mean,
            "confidence_median": conf_median,
            "confidence_stddev": conf_stddev,
            "confidence_min": round(min(confs), 3) if confs else 0.0,
            "confidence_max": round(max(confs), 3) if confs else 0.0,
            "low_confidence_count": low_count,
            "histogram": histogram,
            "flags": flags,
        })

    report = TestReport(
        report_type="confidence",
        timestamp=datetime.now(timezone.utc).isoformat(),
        engine_versions={engine_name: "1.0.0"},
        summary={
            "patterns_analyzed": len(confidences),
            "total_findings": sum(len(v) for v in confidences.values()),
            "flagged_patterns": flagged,
        },
        results=results_data,
    )
    return report


def main():
    _OUTPUT_DIR.mkdir(exist_ok=True)
    report = run_confidence_analysis()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = _OUTPUT_DIR / f"confidence_{timestamp}.json"
    output_path.write_text(report.model_dump_json(indent=2))
    print(f"Report written to {output_path}")
    print(f"Patterns analyzed: {report.summary['patterns_analyzed']}")
    print(f"Total findings: {report.summary['total_findings']}")
    if report.summary["flagged_patterns"]:
        print(f"\nFlagged patterns:")
        for flag in report.summary["flagged_patterns"]:
            print(f"  - {flag}")
    else:
        print("No patterns flagged.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the report**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python reports/confidence_analysis.py`
Expected: Produces JSON in `output/` and prints summary with any flagged patterns.

- [ ] **Step 3: Commit**

```bash
git add reports/confidence_analysis.py
git commit -m "feat: add confidence distribution analysis report"
```

---

### Task 15: Parity Report Script

**Files:**
- Create: `classifinder-tests/reports/parity_report.py`

- [ ] **Step 1: Write parity report script**

```python
# classifinder-tests/reports/parity_report.py
"""Detailed cross-engine parity report.

Runs every corpus file through both engines and diffs results finding-by-finding.
More detailed than test_parity.py — includes allowed divergences and full context.

Usage:
    cd classifinder-tests
    PYTHONPATH=. python reports/parity_report.py
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from lib.engine_wrapper import EngineWrapper
from lib.corpus_parser import parse_corpus_file
from lib.comparator import compare_results
from lib.schema import ParityDivergence, TestReport

_CORPUS_DIR = _PROJECT_ROOT / "corpus"
_OUTPUT_DIR = _PROJECT_ROOT / "output"


def run_parity_report() -> TestReport:
    api_engine = EngineWrapper("api")
    standalone_engine = EngineWrapper("standalone")
    files = sorted(_CORPUS_DIR.rglob("*.txt"))

    all_divergences: list[dict] = []
    allowed_count = 0
    unallowed_count = 0

    for corpus_file in files:
        expectation = parse_corpus_file(corpus_file)
        if not expectation.text.strip():
            continue

        text_hash = hashlib.sha256(expectation.text.encode()).hexdigest()[:16]
        api_results = api_engine.scan(expectation.text, min_confidence=0.0)
        standalone_results = standalone_engine.scan(
            expectation.text, min_confidence=0.0
        )

        divergences = compare_results(api_results, standalone_results)
        for d in divergences:
            if d.allowed:
                allowed_count += 1
            else:
                unallowed_count += 1
            all_divergences.append(ParityDivergence(
                input_text_hash=text_hash,
                pattern_id=d.pattern_id,
                field=d.field,
                api_value=d.api_value,
                standalone_value=d.standalone_value,
                allowed=d.allowed,
                reason=d.reason,
            ).model_dump())

    report = TestReport(
        report_type="parity",
        timestamp=datetime.now(timezone.utc).isoformat(),
        engine_versions={"api": "1.0.0", "standalone": "1.0.0"},
        summary={
            "files_compared": len(files),
            "total_divergences": len(all_divergences),
            "allowed_divergences": allowed_count,
            "unallowed_divergences": unallowed_count,
        },
        results=all_divergences,
    )
    return report


def main():
    _OUTPUT_DIR.mkdir(exist_ok=True)
    report = run_parity_report()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = _OUTPUT_DIR / f"parity_{timestamp}.json"
    output_path.write_text(report.model_dump_json(indent=2))
    print(f"Report written to {output_path}")
    print(f"Files compared: {report.summary['files_compared']}")
    print(f"Total divergences: {report.summary['total_divergences']}")
    print(f"  Allowed: {report.summary['allowed_divergences']}")
    print(f"  Unallowed: {report.summary['unallowed_divergences']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the report**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python reports/parity_report.py`
Expected: Produces JSON in `output/` and prints divergence summary.

- [ ] **Step 3: Commit**

```bash
git add reports/parity_report.py
git commit -m "feat: add cross-engine parity report script"
```

---

### Task 16: Text Report Formatter

**Files:**
- Create: `classifinder-tests/reports/format_text.py`

- [ ] **Step 1: Write text formatter**

```python
# classifinder-tests/reports/format_text.py
"""Human-readable formatter for TestReport JSON files.

Reads any report JSON from output/ and renders a table to stdout.

Usage:
    cd classifinder-tests
    PYTHONPATH=. python reports/format_text.py output/corpus_*.json
    PYTHONPATH=. python reports/format_text.py output/confidence_*.json
    PYTHONPATH=. python reports/format_text.py output/parity_*.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _format_corpus(report: dict) -> str:
    lines = ["=" * 70, "CORPUS REPORT", "=" * 70]
    lines.append(f"Files scanned: {report['summary']['files_scanned']}")
    lines.append(f"Patterns seen: {report['summary']['patterns_seen']}")
    lines.append(f"TP: {report['summary']['total_true_positives']} | "
                 f"FP: {report['summary']['total_false_positives']} | "
                 f"FN: {report['summary']['total_false_negatives']}")
    lines.append("")
    lines.append(f"{'Pattern':<35} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'Conf':>6}")
    lines.append("-" * 70)
    for r in report["results"]:
        lines.append(
            f"{r['pattern_id']:<35} {r['true_positives']:>4} "
            f"{r['false_positives']:>4} {r['false_negatives']:>4} "
            f"{r['precision']:>6.3f} {r['recall']:>6.3f} "
            f"{r['confidence_mean']:>6.3f}"
        )
    return "\n".join(lines)


def _format_confidence(report: dict) -> str:
    lines = ["=" * 70, "CONFIDENCE ANALYSIS", "=" * 70]
    lines.append(f"Patterns analyzed: {report['summary']['patterns_analyzed']}")
    lines.append(f"Total findings: {report['summary']['total_findings']}")
    lines.append("")
    lines.append(f"{'Pattern':<35} {'N':>4} {'Mean':>6} {'Med':>6} {'Std':>6} {'Flags'}")
    lines.append("-" * 70)
    for r in report["results"]:
        flags = ", ".join(r.get("flags", []))
        lines.append(
            f"{r['pattern_id']:<35} {r['sample_count']:>4} "
            f"{r['confidence_mean']:>6.3f} {r['confidence_median']:>6.3f} "
            f"{r['confidence_stddev']:>6.3f} {flags}"
        )
    if report["summary"]["flagged_patterns"]:
        lines.append("")
        lines.append("FLAGGED PATTERNS:")
        for flag in report["summary"]["flagged_patterns"]:
            lines.append(f"  ! {flag}")
    return "\n".join(lines)


def _format_parity(report: dict) -> str:
    lines = ["=" * 70, "PARITY REPORT", "=" * 70]
    lines.append(f"Files compared: {report['summary']['files_compared']}")
    lines.append(f"Divergences: {report['summary']['total_divergences']} "
                 f"(allowed: {report['summary']['allowed_divergences']}, "
                 f"unallowed: {report['summary']['unallowed_divergences']})")
    if report["results"]:
        lines.append("")
        lines.append(f"{'Pattern':<30} {'Field':<12} {'API':<20} {'Standalone':<20} {'OK?'}")
        lines.append("-" * 70)
        for r in report["results"]:
            ok = "yes" if r["allowed"] else "NO"
            lines.append(
                f"{r['pattern_id']:<30} {r['field']:<12} "
                f"{str(r['api_value']):<20} {str(r['standalone_value']):<20} {ok}"
            )
    else:
        lines.append("\nPerfect parity — no divergences found.")
    return "\n".join(lines)


_FORMATTERS = {
    "corpus": _format_corpus,
    "confidence": _format_confidence,
    "parity": _format_parity,
}


def format_report(report_path: Path) -> str:
    data = json.loads(report_path.read_text())
    report_type = data.get("report_type", "unknown")
    formatter = _FORMATTERS.get(report_type)
    if not formatter:
        return f"Unknown report type: {report_type}"
    return formatter(data)


def main():
    if len(sys.argv) < 2:
        print("Usage: python reports/format_text.py <report.json> [report2.json ...]")
        sys.exit(1)

    for path_str in sys.argv[1:]:
        path = Path(path_str)
        if not path.exists():
            print(f"File not found: {path}")
            continue
        print(format_report(path))
        print()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test with an existing report**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python reports/corpus_report.py && PYTHONPATH=. python reports/format_text.py output/corpus_*.json`
Expected: Produces human-readable table output.

- [ ] **Step 3: Commit**

```bash
git add reports/format_text.py
git commit -m "feat: add human-readable text formatter for report JSON"
```

---

### Task 17: Final Integration Test

**Files:** None new — this validates everything works together.

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python -m pytest tests/ -v`
Expected: All tests pass. Note exact count.

- [ ] **Step 2: Run all report scripts**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests
PYTHONPATH=. python reports/corpus_report.py
PYTHONPATH=. python reports/confidence_analysis.py
PYTHONPATH=. python reports/parity_report.py
```
Expected: Three JSON files in `output/`.

- [ ] **Step 3: Format all reports**

Run: `cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests && PYTHONPATH=. python reports/format_text.py output/*.json`
Expected: Human-readable output for all three reports.

- [ ] **Step 4: Review and fix any issues found**

Examine the report output. If any patterns have 0 recall, investigate whether the corpus examples are correct or the engine has a bug. If false positive rates are high for specific patterns, note them for future work.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: integration verification — all tests and reports passing"
```
