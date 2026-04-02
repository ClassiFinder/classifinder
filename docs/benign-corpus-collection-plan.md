# Benign Corpus Collection Plan

> **For agentic workers:** This plan describes data to collect and place into `classifinder-tests/corpus/benign/`. The goal is to build a corpus of text that should NOT trigger secret detection — used to measure false positive rates across ClassiFinder's 82 patterns.

**Goal:** Populate `classifinder-tests/corpus/benign/` with diverse, realistic text that exercises ClassiFinder's pattern regexes without containing real secrets. High false positive rates on this corpus reveal patterns that are too permissive.

**Output location:** `classifinder-tests/corpus/benign/` (already scaffolded with subdirs)

**File convention:** Every file must start with `# expect: none` header. See `classifinder-tests/corpus/README.md` for full convention.

---

## Category 1: Prose (`corpus/benign/prose/`)

Plain English text that should produce zero findings. Tests whether patterns over-match on natural language.

### Files to Create

- [ ] **`prose/technical_blog_post.txt`** — Write or source a 500-1000 word blog post about API security best practices. Should mention "API keys", "tokens", "credentials", "secrets" as concepts without containing actual key formats. Tests context keyword proximity without real matches.

- [ ] **`prose/aws_documentation.txt`** — Excerpt from AWS docs explaining how to configure credentials. Will mention `AKIA`, `AWS_SECRET_ACCESS_KEY`, credential file paths, etc. as prose — not as actual keys. Tests whether the engine triggers on documentation *about* keys.

- [ ] **`prose/security_incident_writeup.txt`** — A mock incident report describing a leaked credential event. Mentions key types, rotation procedures, and remediation steps. Should reference patterns like "the leaked key began with sk_live_" without including a full key.

- [ ] **`prose/changelog.txt`** — A mock CHANGELOG.md with entries like "Fixed API key validation", "Added support for Bearer tokens", "Updated Stripe integration". Dense with keywords but no actual secrets.

- [ ] **`prose/code_review_comments.txt`** — Mock PR review comments: "This looks like it could leak the database connection string", "Make sure the JWT is validated before parsing", "The OpenAI key should be loaded from env vars". Natural language about secrets.

## Category 2: Code (`corpus/benign/code/`)

Source code that talks about secrets, handles credentials, or contains high-entropy strings — but doesn't contain real ones.

### Files to Create

- [ ] **`code/python_config_loader.txt`** — A Python module that loads credentials from environment variables. Uses `os.getenv("AWS_ACCESS_KEY_ID")`, `os.getenv("STRIPE_SECRET_KEY")`, etc. The variable names match pattern keywords but the values are never present.

- [ ] **`code/javascript_auth_middleware.txt`** — Express.js middleware that validates API keys from headers. Contains string literals like `"X-API-Key"`, `"Authorization"`, `"Bearer "` but no actual tokens.

- [ ] **`code/go_database_connect.txt`** — Go code building connection strings from config. Contains format strings like `fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, pass, host, port, db)` — the template without values.

- [ ] **`code/terraform_variables.txt`** — Terraform variable declarations for cloud credentials. Has `variable "aws_access_key" {}`, `variable "database_url" {}` — declarations without defaults or values.

- [ ] **`code/python_test_mocks.txt`** — Python test file that mocks API clients. Contains mock return values, fake response objects, and test assertions. May include placeholder strings like `"test-key-placeholder"` or `"mock-token-12345"`.

- [ ] **`code/base64_image_handling.txt`** — Python/JS code that encodes/decodes base64 images. Contains long base64 strings that are image data, not secrets. Tests whether generic high-entropy patterns over-trigger on legitimate base64 content.

- [ ] **`code/jwt_validation_library.txt`** — Code that parses and validates JWTs but doesn't contain actual tokens. Has regex patterns for JWT format matching, header parsing logic, and signature verification. Tests whether the engine matches on JWT-handling code rather than actual JWTs.

## Category 3: Config Templates (`corpus/benign/config-templates/`)

Configuration files with placeholder values. These are the highest false-positive risk — they look exactly like secret-containing configs but use dummy values.

### Files to Create

- [ ] **`config-templates/env_example.txt`** — A typical `.env.example` file:
  ```
  AWS_ACCESS_KEY_ID=your_aws_access_key_here
  AWS_SECRET_ACCESS_KEY=your_aws_secret_key_here
  STRIPE_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxx
  DATABASE_URL=postgres://user:password@localhost:5432/dbname
  OPENAI_API_KEY=sk-your-openai-key-here
  REDIS_URL=redis://localhost:6379/0
  ```
  These placeholder values should NOT trigger findings. If they do, patterns are too loose.

- [ ] **`config-templates/docker_compose.txt`** — A docker-compose.yml with environment variable references (`${DB_PASSWORD}`) and default placeholder values.

- [ ] **`config-templates/kubernetes_secrets_manifest.txt`** — A K8s Secret manifest with base64-encoded placeholder values. Tests whether the engine triggers on K8s-style base64 that decodes to `"placeholder"`.

- [ ] **`config-templates/github_actions_workflow.txt`** — A CI workflow referencing `${{ secrets.AWS_ACCESS_KEY_ID }}` and `${{ secrets.STRIPE_KEY }}`. Contains secret names as references but not values.

- [ ] **`config-templates/terraform_tfvars_example.txt`** — A `.tfvars.example` with `aws_access_key = "REPLACE_ME"` and similar placeholders.

## Category 4: Encoded Content (`corpus/benign/encoded/`)

High-entropy strings that aren't secrets. Tests the entropy calculator and generic patterns.

### Files to Create

- [ ] **`encoded/base64_payloads.txt`** — Several base64-encoded strings that decode to mundane content: JSON objects, HTML snippets, plain text. Long enough to look like secrets (40+ chars of base64).

- [ ] **`encoded/uuid_heavy_log.txt`** — Log output full of UUIDs (`550e8400-e29b-41d4-a716-446655440000` format). UUIDs are high-entropy and appear in contexts where secrets might (request IDs, session IDs). Should not trigger.

- [ ] **`encoded/hash_values.txt`** — SHA-256 and MD5 hashes of files, git commit SHAs, content hashes. 64-char hex strings that look like API keys but are just hashes. Format: `sha256: abcdef1234...` or git log output.

- [ ] **`encoded/public_jwt_examples.txt`** — JWTs from public documentation (jwt.io examples, RFC examples). These are well-known public tokens with no secret value. Tests whether the engine flags them despite being publicly known.

---

## Collection Guidelines

1. **No real secrets.** Every string in the corpus must be synthetic, placeholder, or publicly known. If sourcing from real repos, strip any string that could be a real credential.

2. **Realistic formatting.** Files should look like real-world content — proper indentation, realistic variable names, plausible structure. The more realistic, the better the false positive signal.

3. **Target high-risk patterns.** Prioritize content that exercises:
   - `generic_high_entropy` — the loosest pattern, most likely to false-positive
   - `generic_api_key` — matches on `key=...` patterns
   - `password_in_url` — matches on `://user:pass@host` patterns
   - `bearer_token` — matches on `Bearer ...` patterns
   - Connection string patterns — any `://...` with credentials

4. **File size.** Each file should be 50-200 lines. Large enough to be a meaningful test, small enough to review manually.

5. **Verify after creation.** After creating each file, scan it through the engine:
   ```bash
   cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests
   PYTHONPATH=. python -c "
   from lib.engine_wrapper import EngineWrapper
   from lib.corpus_parser import parse_corpus_file
   from pathlib import Path
   engine = EngineWrapper('api')
   exp = parse_corpus_file(Path('corpus/benign/prose/technical_blog_post.txt'))
   results = engine.scan(exp.text, min_confidence=0.0)
   if results:
       print('FALSE POSITIVES FOUND:')
       for r in results:
           print(f'  {r.type} (confidence={r.confidence}) at {r.span}')
   else:
       print('Clean — no findings.')
   "
   ```
   If findings are detected, that's useful data — keep the file as-is. The false positives are the whole point. Note which patterns triggered.

6. **Run corpus report after adding files:**
   ```bash
   cd /Users/thomasparas/Documents/ClassiFinder/classifinder-tests
   PYTHONPATH=. python reports/corpus_report.py
   PYTHONPATH=. python reports/format_text.py output/corpus_*.json
   ```

## Priority Order

1. Config templates (highest false positive risk)
2. Code samples (contain pattern keywords in context)
3. Encoded content (tests entropy-based patterns)
4. Prose (lowest risk but good baseline)
