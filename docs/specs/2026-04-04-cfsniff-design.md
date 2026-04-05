# cfsniff — Design Spec

Version: 1.0.0-draft
Date: 2026-04-04

---

## Overview

`cfsniff` is a Python CLI that sniffs out secrets in arbitrary text using the ClassiFinder API. It scans files, directories, stdin, clipboard contents, and well-known non-code locations on the user's machine. Rich terminal output by default, with plain/JSON modes for scripting and an optional self-contained HTML report.

**Why it exists:** ClassiFinder's value proposition is hard to grasp from an API spec. `cfsniff` makes it visceral — run `cfsniff audit` on your machine and see what's leaking. It also dogfoods the `classifinder` Python SDK and drives real API usage.

**What it is not:** A git scanner. TruffleHog, Gitleaks, and detect-secrets already cover repositories. `cfsniff` targets everything *outside* code: shell history, config files, exported chat logs, log files, clipboard contents.

---

## Installation & Auth

```bash
pip install cfsniff
```

Requires a ClassiFinder API key, resolved in this order:

1. `--api-key` flag
2. `CLASSIFINDER_API_KEY` environment variable
3. `~/.cfsniff/config.toml` (future — out of scope for v1)

If no key is found, print a helpful error pointing to https://classifinder.ai to get one.

---

## Commands & Usage

### Direct scanning

```bash
cfsniff <file>                     # scan a single file
cfsniff <dir>                      # scan a directory recursively
cfsniff <file1> <file2> <dir>      # scan multiple targets
echo "sk_live_abc123" | cfsniff    # scan stdin (detected via isatty check)
cfsniff -                          # explicit stdin
cfsniff --clipboard                # scan current clipboard contents
```

**Directory scanning behavior:**

- Recursive by default
- Skips binary files (detect via null bytes in first 8KB)
- Skips files larger than 1 MB (configurable via `--max-file-size`)
- Respects `.gitignore` if present (skip `.git/`, `node_modules/`, etc.)
- No hidden file filtering — hidden files are often where secrets live

### Audit mode

```bash
cfsniff audit                      # scan all default locations
cfsniff audit --include logs       # also scan system/app log files
cfsniff audit --report out.html    # generate HTML report
cfsniff audit --report out.html --open  # generate and open in browser
```

Audit scans a curated list of non-code locations grouped by category:

| Category | Locations |
|----------|-----------|
| Shell history | `~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history` |
| Shell config | `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile` |
| Environment | `~/.env`, any `.env` files in `~/`, `~/Desktop/`, `~/Documents/`, `~/Downloads/` |
| Cloud credentials | `~/.aws/credentials`, `~/.aws/config`, `~/.azure/credentials`, `~/.config/gcloud/credentials.db` (skip, binary), `~/.config/gcloud/application_default_credentials.json` |
| Package managers | `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.composer/auth.json` |
| Container/K8s | `~/.docker/config.json`, `~/.kube/config` |
| SSH | `~/.ssh/config` (not private keys — those are expected to be there) |
| Logs (opt-in) | `~/Library/Logs/**/*.log` (macOS), `/var/log/*.log` (Linux), capped at 50 newest files |

**Audit skips locations that don't exist.** No errors for missing files — many users won't have all of these.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--api-key` | — | ClassiFinder API key (overrides env var) |
| `--format` | `rich` | Output format: `rich`, `plain`, `json` |
| `--min-confidence` | `0.5` | Hide findings below this confidence |
| `--min-severity` | — | Filter by minimum severity: `low`, `medium`, `high`, `critical` |
| `--max-file-size` | `1MB` | Skip files larger than this |
| `--report` | — | Path to write HTML report |
| `--open` | `false` | Open HTML report in browser after generation |
| `--verbose` | `false` | Show which files are being scanned |
| `--version` | — | Print version and exit |
| `--help` | — | Print help and exit |

---

## Output

### Rich format (default)

```
🐕 cfsniff v0.1.0

Scanning 14 files...

~/.bash_history
  line 847  ┃ AWS Access Key     ┃ high   ┃ confidence: 0.95  ┃ AKIA****MPLE
  line 1203 ┃ Stripe Secret Key  ┃ high   ┃ confidence: 0.97  ┃ sk_l****e789

~/.aws/credentials
  line 3    ┃ AWS Secret Key     ┃ high   ┃ confidence: 0.92  ┃ wJal****yBnm

~/.npmrc
  line 1    ┃ NPM Token          ┃ medium ┃ confidence: 0.88  ┃ npm_****F2xK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  4 secrets found across 3 files (14 scanned)
  2 high · 1 medium · 0 low
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Color coding: `high`/`critical` = red, `medium` = yellow, `low` = dim.

Findings are grouped by file, sorted by line number. The summary footer always appears.

### Plain format

```
~/.bash_history:847:aws_access_key:high:0.95:AKIA****MPLE
~/.bash_history:1203:stripe_secret_key:high:0.97:sk_l****e789
~/.aws/credentials:3:aws_secret_key:high:0.92:wJal****yBnm
```

One finding per line, colon-delimited. Suitable for `grep`, `awk`, `wc -l`, etc.

### JSON format

```json
{
  "version": "0.1.0",
  "scanned_files": 14,
  "findings": [
    {
      "file": "~/.bash_history",
      "line": 847,
      "type": "aws_access_key",
      "severity": "high",
      "confidence": 0.95,
      "value_preview": "AKIA****MPLE",
      "span": {"start": 12045, "end": 12065}
    }
  ],
  "summary": {
    "total_findings": 4,
    "files_with_findings": 3,
    "by_severity": {"critical": 0, "high": 2, "medium": 1, "low": 0}
  }
}
```

### HTML report

A single self-contained `.html` file with inline CSS. No JavaScript frameworks, no external dependencies. Can be opened from the filesystem or shared as an attachment.

Contents:
- Header with cfsniff branding (dog emoji, version, scan timestamp)
- Summary stats (files scanned, findings count, severity breakdown)
- Findings table grouped by file, sortable by severity/confidence (minimal vanilla JS for sorting)
- Footer with "Powered by ClassiFinder" link

Visual style: dark theme, consistent with classifinder.ai branding.

---

## Architecture

```
cfsniff (CLI entry point)
  │
  ├── cli.py          — Argument parsing (click or argparse)
  ├── scanner.py      — File discovery, reading, chunking
  ├── api.py          — ClassiFinder SDK wrapper (batching, error handling)
  ├── output.py       — Rich/plain/JSON formatters
  ├── report.py       — HTML report generator
  ├── audit.py        — Audit mode location registry
  └── __main__.py     — Entry point for `python -m cfsniff`
```

### Key design decisions

**Click for CLI parsing.** Argparse is fine for simple CLIs but Click gives us subcommands (`cfsniff audit`), automatic help formatting, and is the standard for Python CLI tools.

**ClassiFinder SDK for API calls.** Uses the `classifinder` pip package directly. No raw HTTP. This dogfoods the SDK and ensures cfsniff benefits from SDK features (retries, error handling).

**File-level batching.** Each file is sent as a single `/v1/scan` request. Files are not concatenated — this preserves line number accuracy. Large files (over the API's max payload size) are skipped with a warning.

**No concurrency in v1.** Files are scanned sequentially. The API latency is low enough that this is fine for dozens of files. Concurrent scanning can be added later if audit mode grows to hundreds of files.

**Value previews come from the API.** cfsniff never constructs its own masked values. It uses `value_preview` from the ClassiFinder response, which masks secrets to first 4 + last 4 characters.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No API key found | Print error with setup instructions, exit 1 |
| Invalid API key (401) | Print "Invalid API key", exit 1 |
| Rate limited (429) | SDK handles retries automatically; if exhausted, print warning and continue with remaining files |
| File not readable (permission denied) | Print warning, skip file, continue |
| Binary file detected | Skip silently (or with `--verbose` note) |
| File too large | Skip with warning |
| Network error | Print error, exit 1 |
| No findings | Print "No secrets found" with count of files scanned, exit 0 |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | No secrets found |
| 1 | Error (auth, network, invalid args) |
| 2 | Secrets found (useful for CI scripting: `cfsniff dir/ && echo clean`) |

---

## Distribution

- **Package name:** `cfsniff` on PyPI
- **Python:** 3.10+ (match SDK requirement)
- **Dependencies:** `classifinder>=0.1.3`, `click>=8.0`, `rich>=13.0`
- **Entry point:** `cfsniff` console script
- **License:** MIT

### Project structure

```
cfsniff/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── cfsniff/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── scanner.py
│       ├── api.py
│       ├── output.py
│       ├── report.py
│       └── audit.py
└── tests/
    ├── test_cli.py
    ├── test_scanner.py
    ├── test_output.py
    └── test_audit.py
```

---

## Out of Scope (v1)

- Config file (`~/.cfsniff/config.toml`) — API key in env var is sufficient for now
- Watch mode / continuous scanning
- Offline mode / local engine fallback
- Plugin system for custom scan locations
- Auto-remediation / secret rotation guidance
- Windows support (macOS and Linux only for v1)
- Pre-commit hook integration (that's TruffleHog territory)

---

## Success Criteria

1. `pip install cfsniff && cfsniff audit` works end-to-end on a fresh machine (with API key set)
2. Audit mode produces a "wow" moment — users see secrets they forgot about
3. HTML report is polished enough to screenshot for marketing
4. The demo flow takes under 30 seconds: install, set key, run audit, see results
5. Drives real ClassiFinder API usage that shows up in logs

---

## Demo Script

This is the flow for Show HN, Product Hunt, README GIF, etc:

```bash
$ pip install cfsniff
$ export CLASSIFINDER_API_KEY=ss_live_your_key_here
$ cfsniff audit

🐕 cfsniff v0.1.0 — sniffing for secrets...

Scanning 23 files across 8 categories...

Shell History
  ~/.zsh_history
    line 1847  ┃ AWS Access Key      ┃ high   ┃ 0.95  ┃ AKIA****MPLE
    line 2103  ┃ Stripe Secret Key   ┃ high   ┃ 0.97  ┃ sk_l****e789

Cloud Credentials
  ~/.aws/credentials
    line 3     ┃ AWS Secret Key      ┃ high   ┃ 0.92  ┃ wJal****yBnm

Package Managers
  ~/.npmrc
    line 1     ┃ NPM Token           ┃ medium ┃ 0.88  ┃ npm_****F2xK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🐕 4 secrets found across 3 files (23 scanned)
  2 high · 1 medium · 0 low

  Run with --report to generate an HTML report
  Powered by ClassiFinder · https://classifinder.ai
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
