# cfsniff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that scans arbitrary text for secrets using the ClassiFinder API, with audit mode for non-code locations and rich terminal + HTML report output.

**Architecture:** Click CLI with two code paths — direct file scanning and audit mode. Files are read locally and sent one-at-a-time to the ClassiFinder API via the `classifinder` SDK. Output is handled by three formatters (rich, plain, JSON) and an optional HTML report generator.

**Tech Stack:** Python 3.10+, Click, Rich, classifinder SDK, pyperclip (clipboard)

---

## File Structure

```
cfsniff/                          # NEW — top-level project directory
├── pyproject.toml                # Package metadata, deps, entry point
├── LICENSE                       # MIT license
├── src/
│   └── cfsniff/
│       ├── __init__.py           # Version constant
│       ├── __main__.py           # python -m cfsniff support
│       ├── cli.py                # Click commands and option parsing
│       ├── scanner.py            # File discovery, reading, binary detection
│       ├── api.py                # ClassiFinder SDK wrapper — scan one file, return enriched results
│       ├── audit.py              # Audit location registry — categories and paths
│       ├── output.py             # Rich/plain/JSON terminal formatters
│       └── report.py             # HTML report generator
└── tests/
    ├── conftest.py               # Shared fixtures (tmp files, mock API responses)
    ├── test_scanner.py           # File discovery and reading tests
    ├── test_api.py               # SDK wrapper tests (mocked HTTP)
    ├── test_audit.py             # Audit location resolution tests
    ├── test_output.py            # Formatter output tests
    ├── test_report.py            # HTML report generation tests
    └── test_cli.py               # End-to-end CLI invocation tests
```

---

### Task 1: Project Scaffold

**Files:**
- Create: `cfsniff/pyproject.toml`
- Create: `cfsniff/LICENSE`
- Create: `cfsniff/src/cfsniff/__init__.py`
- Create: `cfsniff/src/cfsniff/__main__.py`

- [ ] **Step 1: Create project directory**

```bash
mkdir -p cfsniff/src/cfsniff cfsniff/tests
```

- [ ] **Step 2: Create pyproject.toml**

Create `cfsniff/pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "cfsniff"
version = "0.1.0"
description = "Sniff out secrets in arbitrary text using the ClassiFinder API"
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [{ name = "Thomas Paras" }]
dependencies = [
    "classifinder>=0.1.3",
    "click>=8.0",
    "rich>=13.0",
]

[project.optional-dependencies]
clipboard = ["pyperclip>=1.8"]
dev = [
    "pytest>=8.0",
    "respx>=0.21",
    "httpx>=0.27",
    "pyperclip>=1.8",
]

[project.scripts]
cfsniff = "cfsniff.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/cfsniff"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 3: Create LICENSE**

Create `cfsniff/LICENSE` with MIT license text, copyright 2026 Thomas Paras.

- [ ] **Step 4: Create __init__.py**

Create `cfsniff/src/cfsniff/__init__.py`:

```python
"""cfsniff — sniff out secrets in arbitrary text."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Create __main__.py**

Create `cfsniff/src/cfsniff/__main__.py`:

```python
"""Support `python -m cfsniff`."""

from cfsniff.cli import main

main()
```

- [ ] **Step 6: Verify project installs**

```bash
cd cfsniff && pip install -e ".[dev]"
```

Expected: installs successfully, `cfsniff --help` will fail (cli.py doesn't exist yet — that's fine).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml LICENSE src/ tests/
git commit -m "feat: scaffold cfsniff project"
```

---

### Task 2: Scanner — File Discovery and Reading

**Files:**
- Create: `cfsniff/src/cfsniff/scanner.py`
- Create: `cfsniff/tests/conftest.py`
- Create: `cfsniff/tests/test_scanner.py`

The scanner module handles: discovering files in directories, reading file content, detecting binary files, enforcing size limits, and reading stdin/clipboard.

- [ ] **Step 1: Write conftest.py with shared fixtures**

Create `cfsniff/tests/conftest.py`:

```python
"""Shared test fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def tmp_tree(tmp_path: Path) -> Path:
    """Create a temp directory with a mix of files for scanning."""
    # Text file with a fake secret
    (tmp_path / "config.env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

    # Nested directory
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "app.conf").write_text("db_password=hunter2\n")

    # Binary file (null bytes)
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")

    # Large file (will be skipped by size limit)
    (tmp_path / "huge.log").write_text("x" * (2 * 1024 * 1024))

    # Hidden file (should NOT be skipped)
    (tmp_path / ".secret").write_text("token=ghp_abc123\n")

    return tmp_path
```

- [ ] **Step 2: Write failing tests for scanner**

Create `cfsniff/tests/test_scanner.py`:

```python
"""Tests for file discovery and reading."""

from __future__ import annotations

from pathlib import Path

from cfsniff.scanner import discover_files, is_binary, read_file_text


class TestIsBinary:
    def test_text_file(self, tmp_path: Path) -> None:
        f = tmp_path / "text.txt"
        f.write_text("hello world")
        assert is_binary(f) is False

    def test_binary_file(self, tmp_path: Path) -> None:
        f = tmp_path / "bin.dat"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert is_binary(f) is True

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty"
        f.write_text("")
        assert is_binary(f) is False


class TestDiscoverFiles:
    def test_single_file(self, tmp_tree: Path) -> None:
        files = discover_files([tmp_tree / "config.env"], max_file_size=1024 * 1024)
        assert len(files) == 1
        assert files[0].name == "config.env"

    def test_directory_recursive(self, tmp_tree: Path) -> None:
        files = discover_files([tmp_tree], max_file_size=1024 * 1024)
        names = {f.name for f in files}
        # Includes text files and hidden files
        assert "config.env" in names
        assert "app.conf" in names
        assert ".secret" in names
        # Skips binary
        assert "image.png" not in names
        # Skips large files
        assert "huge.log" not in names

    def test_nonexistent_skipped(self, tmp_path: Path) -> None:
        files = discover_files([tmp_path / "nope.txt"], max_file_size=1024 * 1024)
        assert files == []

    def test_max_file_size(self, tmp_tree: Path) -> None:
        # Set a tiny max so even config.env is skipped
        files = discover_files([tmp_tree / "config.env"], max_file_size=5)
        assert files == []


class TestReadFileText:
    def test_reads_content(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello\nworld\n")
        content = read_file_text(f)
        assert content == "hello\nworld\n"

    def test_unreadable_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "nope.txt"
        # File doesn't exist
        assert read_file_text(f) is None
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_scanner.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.scanner'`

- [ ] **Step 4: Implement scanner.py**

Create `cfsniff/src/cfsniff/scanner.py`:

```python
"""File discovery, reading, and binary detection."""

from __future__ import annotations

import os
from pathlib import Path

_BINARY_CHECK_SIZE = 8192


def is_binary(path: Path) -> bool:
    """Check if a file is binary by looking for null bytes in the first 8KB."""
    try:
        chunk = path.read_bytes()[:_BINARY_CHECK_SIZE]
    except OSError:
        return False
    return b"\x00" in chunk


def discover_files(
    targets: list[Path],
    max_file_size: int,
) -> list[Path]:
    """Resolve targets (files and dirs) into a flat list of scannable text files.

    Skips binary files, files over max_file_size, and nonexistent paths.
    Recurses into directories. Does not skip hidden files.
    """
    result: list[Path] = []

    for target in targets:
        if not target.exists():
            continue

        if target.is_file():
            if _should_scan(target, max_file_size):
                result.append(target)
        elif target.is_dir():
            for root, dirs, filenames in os.walk(target):
                # Skip .git and node_modules
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
                for name in filenames:
                    path = Path(root) / name
                    if _should_scan(path, max_file_size):
                        result.append(path)

    return sorted(result)


def _should_scan(path: Path, max_file_size: int) -> bool:
    """Check if a file should be scanned (exists, not binary, not too large)."""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0 or size > max_file_size:
        return False
    return not is_binary(path)


def read_file_text(path: Path) -> str | None:
    """Read a file's text content. Returns None if the file can't be read."""
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_scanner.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/cfsniff/scanner.py tests/conftest.py tests/test_scanner.py
git commit -m "feat: file discovery and binary detection"
```

---

### Task 3: Audit — Location Registry

**Files:**
- Create: `cfsniff/src/cfsniff/audit.py`
- Create: `cfsniff/tests/test_audit.py`

The audit module defines categories of scan locations and resolves them to real paths on the machine.

- [ ] **Step 1: Write failing tests for audit**

Create `cfsniff/tests/test_audit.py`:

```python
"""Tests for audit location registry."""

from __future__ import annotations

import platform
from pathlib import Path
from unittest.mock import patch

from cfsniff.audit import AuditCategory, get_audit_locations, resolve_audit_files


class TestGetAuditLocations:
    def test_returns_categories(self) -> None:
        categories = get_audit_locations(include_logs=False)
        names = [c.name for c in categories]
        assert "Shell History" in names
        assert "Shell Config" in names
        assert "Cloud Credentials" in names
        assert "Package Managers" in names
        assert "Container/K8s" in names
        assert "SSH" in names

    def test_logs_excluded_by_default(self) -> None:
        categories = get_audit_locations(include_logs=False)
        names = [c.name for c in categories]
        assert "Logs" not in names

    def test_logs_included_when_requested(self) -> None:
        categories = get_audit_locations(include_logs=True)
        names = [c.name for c in categories]
        assert "Logs" in names


class TestResolveAuditFiles:
    def test_skips_nonexistent_paths(self, tmp_path: Path) -> None:
        category = AuditCategory(
            name="Test",
            paths=[tmp_path / "does_not_exist.txt"],
        )
        files = resolve_audit_files([category])
        assert files == []

    def test_resolves_existing_paths(self, tmp_path: Path) -> None:
        real_file = tmp_path / "secret.env"
        real_file.write_text("SECRET=abc123\n")
        category = AuditCategory(
            name="Test",
            paths=[real_file, tmp_path / "nope.txt"],
        )
        files = resolve_audit_files([category])
        assert len(files) == 1
        assert files[0] == (category, real_file)

    def test_glob_patterns_in_paths(self, tmp_path: Path) -> None:
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (logs_dir / "app.log").write_text("log data\n")
        (logs_dir / "error.log").write_text("error data\n")
        category = AuditCategory(
            name="Logs",
            glob_patterns=[str(logs_dir / "*.log")],
            max_glob_files=50,
        )
        files = resolve_audit_files([category])
        assert len(files) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_audit.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.audit'`

- [ ] **Step 3: Implement audit.py**

Create `cfsniff/src/cfsniff/audit.py`:

```python
"""Audit mode — curated scan locations for non-code secrets."""

from __future__ import annotations

import glob
import platform
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditCategory:
    """A category of files to scan in audit mode."""

    name: str
    paths: list[Path] = field(default_factory=list)
    glob_patterns: list[str] = field(default_factory=list)
    max_glob_files: int = 50


def get_audit_locations(include_logs: bool = False) -> list[AuditCategory]:
    """Return the list of audit categories with their file paths."""
    home = Path.home()

    categories = [
        AuditCategory(
            name="Shell History",
            paths=[
                home / ".bash_history",
                home / ".zsh_history",
                home / ".local" / "share" / "fish" / "fish_history",
            ],
        ),
        AuditCategory(
            name="Shell Config",
            paths=[
                home / ".bashrc",
                home / ".zshrc",
                home / ".profile",
                home / ".bash_profile",
            ],
        ),
        AuditCategory(
            name="Environment",
            paths=[home / ".env"],
            glob_patterns=[
                str(home / ".env*"),
                str(home / "Desktop" / ".env*"),
                str(home / "Documents" / ".env*"),
                str(home / "Downloads" / ".env*"),
            ],
        ),
        AuditCategory(
            name="Cloud Credentials",
            paths=[
                home / ".aws" / "credentials",
                home / ".aws" / "config",
                home / ".azure" / "credentials",
                home / ".config" / "gcloud" / "application_default_credentials.json",
            ],
        ),
        AuditCategory(
            name="Package Managers",
            paths=[
                home / ".npmrc",
                home / ".pypirc",
                home / ".gem" / "credentials",
                home / ".composer" / "auth.json",
            ],
        ),
        AuditCategory(
            name="Container/K8s",
            paths=[
                home / ".docker" / "config.json",
                home / ".kube" / "config",
            ],
        ),
        AuditCategory(
            name="SSH",
            paths=[home / ".ssh" / "config"],
        ),
    ]

    if include_logs:
        log_category = AuditCategory(name="Logs", max_glob_files=50)
        if platform.system() == "Darwin":
            log_category.glob_patterns.append(str(home / "Library" / "Logs" / "**" / "*.log"))
        else:
            log_category.glob_patterns.append("/var/log/*.log")
        categories.append(log_category)

    return categories


def resolve_audit_files(
    categories: list[AuditCategory],
) -> list[tuple[AuditCategory, Path]]:
    """Resolve audit categories into (category, path) pairs for existing files."""
    result: list[tuple[AuditCategory, Path]] = []
    seen: set[Path] = set()

    for category in categories:
        # Resolve explicit paths
        for path in category.paths:
            resolved = path.expanduser().resolve()
            if resolved not in seen and resolved.is_file():
                seen.add(resolved)
                result.append((category, resolved))

        # Resolve glob patterns
        glob_files: list[Path] = []
        for pattern in category.glob_patterns:
            for match in glob.glob(pattern, recursive=True):
                p = Path(match).resolve()
                if p not in seen and p.is_file():
                    glob_files.append(p)
                    seen.add(p)

        # Sort by modification time (newest first), cap at max
        glob_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for p in glob_files[: category.max_glob_files]:
            result.append((category, p))

    return result
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_audit.py -v
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cfsniff/audit.py tests/test_audit.py
git commit -m "feat: audit location registry"
```

---

### Task 4: API Wrapper

**Files:**
- Create: `cfsniff/src/cfsniff/api.py`
- Create: `cfsniff/tests/test_api.py`

Thin wrapper around the ClassiFinder SDK that scans a single file's text and returns enriched results with line numbers.

- [ ] **Step 1: Write failing tests for api**

Create `cfsniff/tests/test_api.py`:

```python
"""Tests for the ClassiFinder API wrapper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cfsniff.api import FileFinding, scan_text


def _make_mock_finding(
    *,
    type_name: str = "AWS Access Key",
    type: str = "aws_access_key",
    severity: str = "high",
    confidence: float = 0.95,
    value_preview: str = "AKIA****MPLE",
    span_start: int = 0,
    span_end: int = 20,
) -> MagicMock:
    finding = MagicMock()
    finding.type = type
    finding.type_name = type_name
    finding.severity = severity
    finding.confidence = confidence
    finding.value_preview = value_preview
    finding.span = MagicMock(start=span_start, end=span_end)
    return finding


class TestScanText:
    def test_returns_findings_with_line_numbers(self) -> None:
        text = "line one\nAKIAIOSFODNN7EXAMPLE\nline three\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=9, span_end=29),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)

        assert len(findings) == 1
        assert findings[0].line == 2
        assert findings[0].type_name == "AWS Access Key"
        assert findings[0].severity == "high"

    def test_empty_text_returns_empty(self) -> None:
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = []
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, "", min_confidence=0.5)
        assert findings == []

    def test_line_number_calculation(self) -> None:
        # "aaa\nbbb\nccc\n" — span in 3rd line starts at offset 8
        text = "aaa\nbbb\nccc\n"
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.findings = [
            _make_mock_finding(span_start=8, span_end=11),
        ]
        mock_client.scan.return_value = mock_result

        findings = scan_text(mock_client, text, min_confidence=0.5)
        assert findings[0].line == 3
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_api.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.api'`

- [ ] **Step 3: Implement api.py**

Create `cfsniff/src/cfsniff/api.py`:

```python
"""ClassiFinder SDK wrapper — scan text and enrich results with line numbers."""

from __future__ import annotations

from dataclasses import dataclass

from classifinder import ClassiFinder


@dataclass
class FileFinding:
    """A single finding enriched with line number."""

    line: int
    type: str
    type_name: str
    severity: str
    confidence: float
    value_preview: str
    span_start: int
    span_end: int


def _offset_to_line(text: str, offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return text[:offset].count("\n") + 1


def scan_text(
    client: ClassiFinder,
    text: str,
    min_confidence: float = 0.5,
) -> list[FileFinding]:
    """Scan text via the ClassiFinder API and return findings with line numbers."""
    if not text:
        result = client.scan(text, min_confidence=min_confidence)
        return []

    result = client.scan(text, min_confidence=min_confidence)

    return [
        FileFinding(
            line=_offset_to_line(text, f.span.start),
            type=f.type,
            type_name=f.type_name,
            severity=f.severity,
            confidence=f.confidence,
            value_preview=f.value_preview,
            span_start=f.span.start,
            span_end=f.span.end,
        )
        for f in result.findings
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_api.py -v
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cfsniff/api.py tests/test_api.py
git commit -m "feat: API wrapper with line number enrichment"
```

---

### Task 5: Output Formatters

**Files:**
- Create: `cfsniff/src/cfsniff/output.py`
- Create: `cfsniff/tests/test_output.py`

Three output modes: rich (colored terminal), plain (colon-delimited, pipe-friendly), and JSON.

- [ ] **Step 1: Write failing tests for output**

Create `cfsniff/tests/test_output.py`:

```python
"""Tests for output formatters."""

from __future__ import annotations

import json
from pathlib import Path

from cfsniff.api import FileFinding
from cfsniff.output import format_json, format_plain, ScanSummary


def _finding(
    *,
    line: int = 10,
    type: str = "aws_access_key",
    type_name: str = "AWS Access Key",
    severity: str = "high",
    confidence: float = 0.95,
    value_preview: str = "AKIA****MPLE",
) -> FileFinding:
    return FileFinding(
        line=line,
        type=type,
        type_name=type_name,
        severity=severity,
        confidence=confidence,
        value_preview=value_preview,
        span_start=0,
        span_end=20,
    )


class TestFormatPlain:
    def test_single_finding(self) -> None:
        file_findings = [(Path("/home/user/.env"), [_finding()])]
        lines = format_plain(file_findings)
        assert lines == ["/home/user/.env:10:aws_access_key:high:0.95:AKIA****MPLE"]

    def test_multiple_findings(self) -> None:
        file_findings = [
            (Path("/home/.env"), [_finding(line=1), _finding(line=5, type="stripe_secret_key", type_name="Stripe Key", severity="medium", confidence=0.88, value_preview="sk_l****789")]),
        ]
        lines = format_plain(file_findings)
        assert len(lines) == 2
        assert "stripe_secret_key" in lines[1]

    def test_empty_findings(self) -> None:
        lines = format_plain([])
        assert lines == []


class TestFormatJson:
    def test_structure(self) -> None:
        file_findings = [(Path("/home/.env"), [_finding()])]
        summary = ScanSummary(scanned_files=5, total_findings=1, files_with_findings=1, by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0})
        data = json.loads(format_json(file_findings, summary))
        assert data["scanned_files"] == 5
        assert len(data["findings"]) == 1
        assert data["findings"][0]["file"] == "/home/.env"
        assert data["findings"][0]["line"] == 10
        assert data["summary"]["total_findings"] == 1

    def test_empty(self) -> None:
        summary = ScanSummary(scanned_files=0, total_findings=0, files_with_findings=0, by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0})
        data = json.loads(format_json([], summary))
        assert data["findings"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_output.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.output'`

- [ ] **Step 3: Implement output.py**

Create `cfsniff/src/cfsniff/output.py`:

```python
"""Terminal output formatters: rich, plain, and JSON."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from cfsniff import __version__
from cfsniff.api import FileFinding

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


@dataclass
class ScanSummary:
    scanned_files: int
    total_findings: int
    files_with_findings: int
    by_severity: dict[str, int]


def format_plain(file_findings: list[tuple[Path, list[FileFinding]]]) -> list[str]:
    """Format findings as colon-delimited lines for piping."""
    lines: list[str] = []
    for path, findings in file_findings:
        for f in findings:
            lines.append(f"{path}:{f.line}:{f.type}:{f.severity}:{f.confidence:.2f}:{f.value_preview}")
    return lines


def format_json(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
) -> str:
    """Format findings as JSON."""
    findings_list = []
    for path, findings in file_findings:
        for f in findings:
            findings_list.append({
                "file": str(path),
                "line": f.line,
                "type": f.type,
                "type_name": f.type_name,
                "severity": f.severity,
                "confidence": f.confidence,
                "value_preview": f.value_preview,
                "span": {"start": f.span_start, "end": f.span_end},
            })

    output = {
        "version": __version__,
        "scanned_files": summary.scanned_files,
        "findings": findings_list,
        "summary": asdict(summary),
    }
    return json.dumps(output, indent=2)


def print_rich(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
    console: Console | None = None,
) -> None:
    """Print findings with rich formatting."""
    console = console or Console()
    console.print(f"\n[bold]cfsniff[/bold] v{__version__}\n")

    if not file_findings:
        console.print(f"[green]No secrets found[/green] ({summary.scanned_files} files scanned)")
        return

    for path, findings in file_findings:
        console.print(f"\n[bold]{path}[/bold]")
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            console.print(
                f"  line {f.line:<6} | {f.type_name:<22} | [{color}]{f.severity:<8}[/{color}] | {f.confidence:.2f} | {f.value_preview}"
            )

    console.print()
    console.rule()
    sev = summary.by_severity
    console.print(
        f"  {summary.total_findings} secrets found across "
        f"{summary.files_with_findings} files ({summary.scanned_files} scanned)"
    )
    console.print(
        f"  [red]{sev.get('high', 0) + sev.get('critical', 0)} high[/red] · "
        f"[yellow]{sev.get('medium', 0)} medium[/yellow] · "
        f"[dim]{sev.get('low', 0)} low[/dim]"
    )
    console.rule()
    console.print()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_output.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cfsniff/output.py tests/test_output.py
git commit -m "feat: plain and JSON output formatters with rich printing"
```

---

### Task 6: HTML Report Generator

**Files:**
- Create: `cfsniff/src/cfsniff/report.py`
- Create: `cfsniff/tests/test_report.py`

Generates a single self-contained HTML file with dark theme styling.

- [ ] **Step 1: Write failing tests for report**

Create `cfsniff/tests/test_report.py`:

```python
"""Tests for HTML report generation."""

from __future__ import annotations

from pathlib import Path

from cfsniff.api import FileFinding
from cfsniff.output import ScanSummary
from cfsniff.report import generate_html_report


def _finding(**kwargs) -> FileFinding:
    defaults = dict(
        line=10, type="aws_access_key", type_name="AWS Access Key",
        severity="high", confidence=0.95, value_preview="AKIA****MPLE",
        span_start=0, span_end=20,
    )
    defaults.update(kwargs)
    return FileFinding(**defaults)


class TestGenerateHtmlReport:
    def test_produces_valid_html(self, tmp_path: Path) -> None:
        file_findings = [(Path("/home/.env"), [_finding()])]
        summary = ScanSummary(
            scanned_files=5, total_findings=1,
            files_with_findings=1,
            by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0},
        )
        html = generate_html_report(file_findings, summary)
        assert "<!DOCTYPE html>" in html
        assert "cfsniff" in html
        assert "AWS Access Key" in html
        assert "AKIA****MPLE" in html
        assert "ClassiFinder" in html

    def test_contains_summary_stats(self) -> None:
        summary = ScanSummary(
            scanned_files=42, total_findings=3,
            files_with_findings=2,
            by_severity={"critical": 0, "high": 2, "medium": 1, "low": 0},
        )
        html = generate_html_report(
            [(Path("/a"), [_finding()]), (Path("/b"), [_finding(), _finding()])],
            summary,
        )
        assert "42" in html  # scanned files
        assert "3" in html   # total findings

    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        summary = ScanSummary(
            scanned_files=1, total_findings=1,
            files_with_findings=1,
            by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0},
        )
        html = generate_html_report(
            [(Path("/test"), [_finding()])], summary,
        )
        out.write_text(html)
        assert out.read_text().startswith("<!DOCTYPE html>")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_report.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.report'`

- [ ] **Step 3: Implement report.py**

Create `cfsniff/src/cfsniff/report.py`:

```python
"""Self-contained HTML report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from cfsniff import __version__
from cfsniff.api import FileFinding
from cfsniff.output import ScanSummary

_SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f87171",
    "medium": "#facc15",
    "low": "#9ca3af",
}


def generate_html_report(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
) -> str:
    """Generate a self-contained HTML report string."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for path, findings in file_findings:
        for i, f in enumerate(findings):
            color = _SEVERITY_COLORS.get(f.severity, "#9ca3af")
            file_cell = html.escape(str(path)) if i == 0 else ""
            rows += f"""<tr>
                <td class="file">{file_cell}</td>
                <td>{f.line}</td>
                <td>{html.escape(f.type_name)}</td>
                <td style="color:{color}">{html.escape(f.severity)}</td>
                <td>{f.confidence:.2f}</td>
                <td><code>{html.escape(f.value_preview)}</code></td>
            </tr>\n"""

    sev = summary.by_severity

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cfsniff audit report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 2rem; }}
  .header {{ text-align: center; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  .header .meta {{ color: #94a3b8; font-size: 0.85rem; }}
  .stats {{ display: flex; gap: 1.5rem; justify-content: center; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; padding: 1rem 1.5rem; border-radius: 8px; text-align: center; }}
  .stat .number {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .label {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th {{ background: #334155; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
  td.file {{ font-weight: 600; color: #93c5fd; }}
  code {{ background: #334155; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
  .footer {{ text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.8rem; }}
  .footer a {{ color: #60a5fa; text-decoration: none; }}
</style>
</head>
<body>
<div class="header">
    <h1>cfsniff audit report</h1>
    <div class="meta">v{__version__} &middot; {timestamp}</div>
</div>
<div class="stats">
    <div class="stat"><div class="number">{summary.total_findings}</div><div class="label">Secrets Found</div></div>
    <div class="stat"><div class="number">{summary.files_with_findings}</div><div class="label">Files Affected</div></div>
    <div class="stat"><div class="number">{summary.scanned_files}</div><div class="label">Files Scanned</div></div>
    <div class="stat"><div class="number" style="color:#f87171">{sev.get('high', 0) + sev.get('critical', 0)}</div><div class="label">High/Critical</div></div>
    <div class="stat"><div class="number" style="color:#facc15">{sev.get('medium', 0)}</div><div class="label">Medium</div></div>
</div>
<table>
    <thead><tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Preview</th></tr></thead>
    <tbody>{rows}</tbody>
</table>
<div class="footer">Powered by <a href="https://classifinder.ai">ClassiFinder</a></div>
</body>
</html>"""
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_report.py -v
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cfsniff/report.py tests/test_report.py
git commit -m "feat: HTML report generator with dark theme"
```

---

### Task 7: CLI — Click Commands and Wiring

**Files:**
- Create: `cfsniff/src/cfsniff/cli.py`
- Create: `cfsniff/tests/test_cli.py`

This is the main wiring task — connects scanner, api, audit, output, and report into Click commands.

- [ ] **Step 1: Write failing tests for CLI**

Create `cfsniff/tests/test_cli.py`:

```python
"""End-to-end CLI tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cfsniff.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def mock_client():
    """Mock ClassiFinder client that returns no findings."""
    with patch("cfsniff.cli.ClassiFinder") as mock_cls:
        client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        result = MagicMock()
        result.findings = []
        client.scan.return_value = result
        yield client


import pytest


class TestMainCommand:
    def test_no_args_no_stdin_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [])
        assert result.exit_code != 0 or "Usage" in result.output or "No targets" in result.output

    def test_scan_file(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing_here\n")
        result = runner.invoke(main, [str(f), "--api-key", "ss_test_key123456789012345678901234567890123"])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_file_plain_format(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing\n")
        result = runner.invoke(main, [str(f), "--api-key", "ss_test_key123456789012345678901234567890123", "--format", "plain"])
        assert result.exit_code == 0

    def test_scan_file_json_format(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("SAFE=nothing\n")
        result = runner.invoke(main, [str(f), "--api-key", "ss_test_key123456789012345678901234567890123", "--format", "json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert data["scanned_files"] >= 1

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output

    def test_missing_api_key(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "test.env"
        f.write_text("data\n")
        with patch.dict("os.environ", {}, clear=True):
            result = runner.invoke(main, [str(f)])
        assert result.exit_code == 1


class TestAuditCommand:
    def test_audit_runs(self, runner: CliRunner, mock_client: MagicMock) -> None:
        result = runner.invoke(main, ["audit", "--api-key", "ss_test_key123456789012345678901234567890123"])
        # Should succeed even if no audit files exist on this machine
        assert result.exit_code == 0

    def test_audit_with_report(self, runner: CliRunner, mock_client: MagicMock, tmp_path: Path) -> None:
        report_path = tmp_path / "report.html"
        result = runner.invoke(main, [
            "audit",
            "--api-key", "ss_test_key123456789012345678901234567890123",
            "--report", str(report_path),
        ])
        assert result.exit_code == 0
        assert report_path.exists()
        assert "<!DOCTYPE html>" in report_path.read_text()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd cfsniff && python -m pytest tests/test_cli.py -v
```

Expected: `ModuleNotFoundError: No module named 'cfsniff.cli'`

- [ ] **Step 3: Implement cli.py**

Create `cfsniff/src/cfsniff/cli.py`:

```python
"""Click CLI entry point for cfsniff."""

from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path

import click
from rich.console import Console

from cfsniff import __version__
from cfsniff.api import FileFinding, scan_text
from cfsniff.audit import get_audit_locations, resolve_audit_files
from cfsniff.output import ScanSummary, format_json, format_plain, print_rich
from cfsniff.report import generate_html_report
from cfsniff.scanner import discover_files, read_file_text

try:
    from classifinder import ClassiFinder
    from classifinder._exceptions import AuthenticationError, ClassiFinderError
except ImportError:
    click.echo("Error: classifinder SDK not installed. Run: pip install classifinder", err=True)
    sys.exit(1)

_DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1 MB


def _resolve_api_key(api_key: str | None) -> str | None:
    """Resolve API key from flag or environment variable."""
    return api_key or os.environ.get("CLASSIFINDER_API_KEY")


def _scan_files(
    client: ClassiFinder,
    files: list[Path],
    min_confidence: float,
    verbose: bool,
    console: Console,
) -> list[tuple[Path, list[FileFinding]]]:
    """Scan a list of files and return (path, findings) pairs."""
    results: list[tuple[Path, list[FileFinding]]] = []
    for path in files:
        if verbose:
            console.print(f"  [dim]scanning {path}[/dim]", highlight=False)
        text = read_file_text(path)
        if text is None:
            if verbose:
                console.print(f"  [yellow]skipped (unreadable): {path}[/yellow]")
            continue
        try:
            findings = scan_text(client, text, min_confidence=min_confidence)
        except ClassiFinderError as exc:
            console.print(f"  [red]error scanning {path}: {exc.message}[/red]", err=True)
            continue
        if findings:
            results.append((path, findings))
    return results


def _filter_severity(
    file_findings: list[tuple[Path, list[FileFinding]]],
    min_severity: str | None,
) -> list[tuple[Path, list[FileFinding]]]:
    """Filter findings by minimum severity."""
    if not min_severity:
        return file_findings
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = order.get(min_severity, 0)
    filtered = []
    for path, findings in file_findings:
        kept = [f for f in findings if order.get(f.severity, 0) >= threshold]
        if kept:
            filtered.append((path, kept))
    return filtered


def _build_summary(
    file_findings: list[tuple[Path, list[FileFinding]]],
    scanned_files: int,
) -> ScanSummary:
    """Build a summary from results."""
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total = 0
    for _, findings in file_findings:
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            total += 1
    return ScanSummary(
        scanned_files=scanned_files,
        total_findings=total,
        files_with_findings=len(file_findings),
        by_severity=by_severity,
    )


def _output_results(
    file_findings: list[tuple[Path, list[FileFinding]]],
    summary: ScanSummary,
    fmt: str,
    report_path: str | None,
    open_report: bool,
    console: Console,
) -> None:
    """Output results in the requested format and optionally generate a report."""
    if fmt == "plain":
        for line in format_plain(file_findings):
            click.echo(line)
    elif fmt == "json":
        click.echo(format_json(file_findings, summary))
    else:
        print_rich(file_findings, summary, console=console)

    if report_path:
        html = generate_html_report(file_findings, summary)
        Path(report_path).write_text(html)
        console.print(f"\n[green]Report written to {report_path}[/green]")
        if open_report:
            webbrowser.open(f"file://{Path(report_path).resolve()}")


@click.group(invoke_without_command=True)
@click.argument("targets", nargs=-1, type=click.Path())
@click.option("--api-key", default=None, help="ClassiFinder API key")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json"]), default="rich", help="Output format")
@click.option("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold")
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None, help="Minimum severity filter")
@click.option("--max-file-size", type=int, default=_DEFAULT_MAX_FILE_SIZE, help="Max file size in bytes")
@click.option("--report", default=None, type=click.Path(), help="Write HTML report to path")
@click.option("--open", "open_report", is_flag=True, help="Open HTML report in browser")
@click.option("--clipboard", is_flag=True, help="Scan clipboard contents")
@click.option("--verbose", is_flag=True, help="Show files being scanned")
@click.version_option(__version__)
@click.pass_context
def main(
    ctx: click.Context,
    targets: tuple[str, ...],
    api_key: str | None,
    fmt: str,
    min_confidence: float,
    min_severity: str | None,
    max_file_size: int,
    report: str | None,
    open_report: bool,
    clipboard: bool,
    verbose: bool,
) -> None:
    """cfsniff — sniff out secrets in arbitrary text."""
    # If a subcommand was invoked, let it handle everything
    if ctx.invoked_subcommand is not None:
        ctx.ensure_object(dict)
        ctx.obj["api_key"] = api_key
        ctx.obj["fmt"] = fmt
        ctx.obj["min_confidence"] = min_confidence
        ctx.obj["min_severity"] = min_severity
        ctx.obj["max_file_size"] = max_file_size
        ctx.obj["report"] = report
        ctx.obj["open_report"] = open_report
        ctx.obj["verbose"] = verbose
        return

    console = Console(stderr=True) if fmt != "rich" else Console()

    # Check for stdin
    reading_stdin = not sys.stdin.isatty() or (targets and targets[0] == "-")

    # Check for clipboard
    clipboard_text = None
    if clipboard:
        try:
            import pyperclip
            clipboard_text = pyperclip.paste()
        except ImportError:
            click.echo("Error: clipboard support requires pyperclip. Run: pip install cfsniff[clipboard]", err=True)
            ctx.exit(1)
            return
        except Exception as exc:
            click.echo(f"Error reading clipboard: {exc}", err=True)
            ctx.exit(1)
            return

    if not targets and not reading_stdin and not clipboard:
        click.echo(ctx.get_help())
        return

    # Resolve API key
    resolved_key = _resolve_api_key(api_key)
    if not resolved_key:
        click.echo(
            "Error: No API key found.\n\n"
            "Set CLASSIFINDER_API_KEY or pass --api-key.\n"
            "Get a key at https://classifinder.ai",
            err=True,
        )
        ctx.exit(1)
        return

    try:
        with ClassiFinder(api_key=resolved_key) as client:
            all_file_findings: list[tuple[Path, list[FileFinding]]] = []
            scanned_count = 0

            # Scan clipboard
            if clipboard_text:
                findings = scan_text(client, clipboard_text, min_confidence=min_confidence)
                scanned_count += 1
                if findings:
                    all_file_findings.append((Path("<clipboard>"), findings))

            # Scan stdin
            if reading_stdin:
                stdin_text = sys.stdin.read()
                findings = scan_text(client, stdin_text, min_confidence=min_confidence)
                scanned_count += 1
                if findings:
                    all_file_findings.append((Path("<stdin>"), findings))

            # Scan file targets (exclude "-" which means stdin)
            file_targets = [Path(t) for t in targets if t != "-"]
            if file_targets:
                files = discover_files(file_targets, max_file_size=max_file_size)
                scanned_count += len(files)
                file_results = _scan_files(client, files, min_confidence, verbose, console)
                all_file_findings.extend(file_results)

            # Filter and output
            all_file_findings = _filter_severity(all_file_findings, min_severity)
            summary = _build_summary(all_file_findings, scanned_count)
            _output_results(all_file_findings, summary, fmt, report, open_report, console)

            # Exit code: 2 if secrets found, 0 if clean
            if summary.total_findings > 0:
                ctx.exit(2)

    except AuthenticationError:
        click.echo("Error: Invalid API key.", err=True)
        ctx.exit(1)
    except ClassiFinderError as exc:
        click.echo(f"Error: {exc.message}", err=True)
        ctx.exit(1)


@main.command()
@click.option("--include", multiple=True, help="Include optional categories (e.g., 'logs')")
@click.option("--api-key", default=None, help="ClassiFinder API key")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json"]), default="rich")
@click.option("--min-confidence", type=float, default=0.5)
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None)
@click.option("--max-file-size", type=int, default=_DEFAULT_MAX_FILE_SIZE)
@click.option("--report", default=None, type=click.Path())
@click.option("--open", "open_report", is_flag=True)
@click.option("--verbose", is_flag=True)
@click.pass_context
def audit(
    ctx: click.Context,
    include: tuple[str, ...],
    api_key: str | None,
    fmt: str,
    min_confidence: float,
    min_severity: str | None,
    max_file_size: int,
    report: str | None,
    open_report: bool,
    verbose: bool,
) -> None:
    """Audit your machine for secrets in non-code locations."""
    console = Console(stderr=True) if fmt != "rich" else Console()

    # Merge options from parent context if present
    obj = ctx.obj or {}
    api_key = api_key or obj.get("api_key")
    fmt = fmt if fmt != "rich" else obj.get("fmt", fmt)

    resolved_key = _resolve_api_key(api_key)
    if not resolved_key:
        click.echo(
            "Error: No API key found.\n\n"
            "Set CLASSIFINDER_API_KEY or pass --api-key.\n"
            "Get a key at https://classifinder.ai",
            err=True,
        )
        ctx.exit(1)
        return

    include_logs = "logs" in include
    categories = get_audit_locations(include_logs=include_logs)
    audit_files = resolve_audit_files(categories)

    if fmt == "rich":
        console.print(f"\n[bold]cfsniff[/bold] v{__version__} — sniffing for secrets...\n")
        console.print(f"Scanning {len(audit_files)} files across {len(categories)} categories...\n")

    try:
        with ClassiFinder(api_key=resolved_key) as client:
            all_file_findings: list[tuple[Path, list[FileFinding]]] = []

            # Group by category for rich output
            current_category = None
            for category, path in audit_files:
                if verbose:
                    console.print(f"  [dim]scanning {path}[/dim]", highlight=False)
                text = read_file_text(path)
                if text is None:
                    continue
                try:
                    findings = scan_text(client, text, min_confidence=min_confidence)
                except ClassiFinderError as exc:
                    if verbose:
                        console.print(f"  [red]error: {path}: {exc.message}[/red]", err=True)
                    continue
                if findings:
                    all_file_findings.append((path, findings))

            all_file_findings = _filter_severity(all_file_findings, min_severity)
            summary = _build_summary(all_file_findings, len(audit_files))
            _output_results(all_file_findings, summary, fmt, report, open_report, console)

            if summary.total_findings > 0:
                ctx.exit(2)

    except AuthenticationError:
        click.echo("Error: Invalid API key.", err=True)
        ctx.exit(1)
    except ClassiFinderError as exc:
        click.echo(f"Error: {exc.message}", err=True)
        ctx.exit(1)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd cfsniff && python -m pytest tests/test_cli.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 5: Run full test suite**

```bash
cd cfsniff && python -m pytest tests/ -v
```

Expected: all tests across all modules pass.

- [ ] **Step 6: Verify CLI works end-to-end**

```bash
cd cfsniff && cfsniff --version
cfsniff --help
echo "AKIAIOSFODNN7EXAMPLE" | cfsniff --api-key ss_test_yourkey123456789012345678901234567890
```

Verify version prints, help shows, and stdin scanning works (if you have a valid API key).

- [ ] **Step 7: Commit**

```bash
git add src/cfsniff/cli.py tests/test_cli.py
git commit -m "feat: CLI wiring — main and audit commands"
```

---

### Task 8: README

**Files:**
- Create: `cfsniff/README.md`

- [ ] **Step 1: Write README**

Create `cfsniff/README.md` with:

- One-line description and dog emoji
- Install instructions (`pip install cfsniff`)
- Quick start (3 commands: install, set key, run audit)
- Usage examples for all modes (file, dir, stdin, clipboard, audit)
- Output format examples (rich, plain, json)
- HTML report section
- Link to ClassiFinder for API key
- License (MIT)

Keep it concise — this is the "scroll through in 30 seconds" README.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

---

### Task 9: Final Integration Test

**Files:**
- No new files — this is a verification task.

- [ ] **Step 1: Run full test suite**

```bash
cd cfsniff && python -m pytest tests/ -v --tb=short
```

Expected: all tests pass.

- [ ] **Step 2: Test editable install from scratch**

```bash
cd /tmp && python -m venv cfsniff-test && source cfsniff-test/bin/activate
cd /path/to/cfsniff && pip install -e ".[dev]"
cfsniff --version
cfsniff --help
python -m pytest tests/ -v
deactivate && rm -rf /tmp/cfsniff-test
```

Expected: clean install, version prints, help shows, all tests pass.

- [ ] **Step 3: Commit any fixes**

If anything needed fixing, commit here.
