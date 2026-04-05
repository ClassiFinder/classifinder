# Pattern Quality Testing Methods — Agent Bootstrap

## Context

ClassiFinder's scanner engine uses 101 regex patterns to detect leaked secrets. We need systematic methods to evaluate and improve pattern quality — specifically false positive rates (matching non-secrets) and false negative rates (missing real secrets).

We cannot rely on user feedback for this because our no-storage security model means we never see the actual strings users report as incorrect. We need to test with our own data.

### Key Files

- **Engine:** `app/engine/` — scanner, redactor, entropy calculator, pattern modules
- **Patterns:** `app/engine/patterns/` — registry + 7 category modules (cloud, database, ai, crypto, messaging, devops, generic)
- **Existing tests:** `tests/test_patterns.py` (21 tests), `tests/test_api.py` (36 tests)
- **Pattern docs:** `docs/pattern-library.md` — all 101 patterns with regexes and examples
- **Engine entry point:** `app/engine/scanner.py` — `scan_text()` function returns findings

Read `CLAUDE.md` at the repo root for architecture overview and `classifinder/CLAUDE.md` for engine details.

## Testing Methods

### 1. Public Corpus Testing (False Positive Focus)

Run the engine against large bodies of public text that should NOT trigger findings, or should trigger very few. High match rates indicate overly permissive patterns.

**Corpus sources:**
- **Open-source READMEs and docs** — GitHub trending repos, popular library docs. These often contain example keys, placeholder tokens, and base64 strings that look like secrets but aren't.
- **Stack Overflow code snippets** — answers frequently include `AKIAIOSFODNN7EXAMPLE`, `sk-test-...`, and other example credentials.
- **Configuration templates** — `.env.example` files, Docker Compose templates, Terraform examples. Full of `YOUR_API_KEY_HERE` patterns.
- **Prose text** — blog posts, articles, books. Should produce zero findings. If the engine matches something in a novel, the pattern is too loose.
- **Base64-heavy content** — JWTs, encoded images, serialized data. Tests whether generic patterns over-trigger on high-entropy strings that aren't secrets.

**How to run:**
```python
from app.engine.scanner import scan_text

# Scan a corpus file and collect findings
results = scan_text(open("corpus/readme_samples.txt").read())
# Audit each finding: is this a real secret or a false positive?
```

**What to build:**
- A `tests/corpus/` directory with curated test files
- A script (`scripts/corpus_test.py`) that scans all corpus files and produces a report: findings per file, findings per pattern, flagged items for manual review
- Track false positive rates per pattern over time

### 2. Known Secret Format Testing (False Negative Focus)

Test with strings that are *known* to be valid secret formats. The engine should catch all of them.

**Sources:**
- **Sanitized leak datasets** — TruffleHog, GitLeaks, and shhgit have published format examples and test fixtures. Mine their test suites for format patterns.
- **Provider documentation** — AWS, GCP, Stripe, OpenAI, etc. all document their key formats. Generate synthetic keys matching the documented format (random but structurally valid).
- **Your own pattern-library.md** — already has example values for each pattern. Verify every single example actually triggers a match with the expected confidence score.

**What to build:**
- A `tests/known_secrets/` directory with one file per pattern category, containing synthetic strings that should match
- A test that asserts every pattern has at least N known-match test cases
- A test that asserts every example in `pattern-library.md` actually matches

### 3. Adversarial / Edge Case Testing

Test boundary conditions and near-misses to understand where patterns break.

**Techniques:**
- **Truncation** — does `AKIA` + 15 chars (instead of 16) trigger a match? It shouldn't.
- **Prefix/suffix noise** — does a key embedded in a URL, a JSON string, or a log line still match? It should.
- **Character substitution** — replace one character in a valid key. Does the pattern still match? (It will — regexes don't validate checksums. This tells you about false positive risk.)
- **Encoding** — base64-encoded secrets, URL-encoded secrets, secrets inside JSON strings with escaped characters. Does the engine catch these?
- **Multi-line secrets** — PEM keys, multi-line connection strings. Are these handled correctly?
- **Near-miss formats** — strings that are close to a pattern but shouldn't match (e.g., a string that starts with `sk_live_` but is only 10 chars total)

**What to build:**
- A `tests/adversarial/` directory organized by technique
- Parameterized pytest tests for each edge case category

### 4. Confidence Distribution Analysis

Run the engine against a large mixed corpus (both real secret formats and benign text) and analyze the confidence score distribution.

**What to look for:**
- **Per-pattern confidence spread** — patterns that consistently score near the minimum (0.05) are probably too permissive and getting entropy-penalized
- **Entropy penalty frequency** — which patterns most often trigger the entropy penalty? These are candidates for tighter regexes that don't need entropy as a crutch
- **Context boost effectiveness** — how often does context boosting push a borderline finding above a useful threshold? If rarely, the keywords may need updating
- **Bimodal distributions** — a pattern that clusters at both 0.15 and 0.90 might be two different things (real secrets vs. test values) caught by one regex

**What to build:**
- A script (`scripts/confidence_analysis.py`) that:
  1. Scans a large corpus
  2. Collects all findings with their confidence scores, entropy values, context boost amounts
  3. Outputs per-pattern statistics: mean, median, stddev, histogram
  4. Flags patterns with concerning distributions (high variance, low mean, frequent entropy penalties)

### 5. Cross-Engine Comparison

Compare ClassiFinder's results against other open-source secret scanners on the same corpus.

**Tools to compare against:**
- TruffleHog
- GitLeaks
- detect-secrets (Yelp)

**What to measure:**
- Findings ClassiFinder catches that others miss (unique value)
- Findings others catch that ClassiFinder misses (gaps)
- Findings all tools agree on (baseline correctness)
- False positive rates across tools on benign text

This gives external validation and highlights coverage gaps. Build as a script that runs all tools on the same input and diffs the results.

## Suggested Build Order

1. **Pattern-library.md validation** — quickest win. Assert every documented example actually matches. This is a test you can write immediately with no external data.
2. **Known secret format tests** — generate synthetic keys for each pattern from provider docs. High value, no external dependencies.
3. **Public corpus collection + false positive testing** — requires curating test data, but reveals the most actionable issues.
4. **Confidence distribution analysis** — needs a corpus first, but gives deep insight into pattern quality.
5. **Adversarial edge cases** — targeted testing based on what you learn from steps 1-4.
6. **Cross-engine comparison** — nice to have, depends on installing other tools.

## Output Expectations

Each testing method should produce:
- Automated tests that can run in CI (`pytest`)
- A report script that produces human-readable output for manual review
- Actionable findings: "pattern X has Y% false positive rate on corpus Z" or "pattern X misses format Y"
