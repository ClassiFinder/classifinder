# Domain Migration: classifinder.tech → classifinder.ai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all production services and references from `classifinder.tech` to `classifinder.ai`, keeping `.tech` as a redirect for existing users.

**Architecture:** DNS zone setup on Cloudflare for `classifinder.ai`, then update Fly.io custom domain, Cloudflare Workers route, all code/docs references, and publish new SDK + MCP versions. The `.tech` domain stays active as a redirect — no existing links or installed SDKs break.

**Tech Stack:** Cloudflare DNS, Fly.io, Cloudflare Workers, Python (SDK + MCP releases), Astro (site)

**Scope note:** `classifinder-test/` is excluded from this plan and will be assessed separately.

---

## File Map

| File | Action | What Changes |
|------|--------|-------------|
| — | Infra | Cloudflare DNS zone for classifinder.ai |
| — | Infra | Fly.io custom domain api.classifinder.ai |
| — | Infra | Cloudflare Workers route for classifinder.ai |
| — | Infra | .tech → .ai redirects on Cloudflare |
| `classifinder-sdk/src/classifinder/_base.py` | Modify | `DEFAULT_BASE_URL` → `https://api.classifinder.ai` |
| `classifinder-sdk/tests/conftest.py` | Modify | `TEST_BASE_URL` → `https://api.classifinder.ai` |
| `classifinder-sdk/README.md` | Modify | Documentation URL |
| `classifinder-sdk/pyproject.toml` | Modify | Version bump 0.1.2 → 0.1.3 |
| `classifinder-mcp/README.md` | Modify | Landing page URL |
| `classifinder-mcp/src/classifinder_mcp/server.py` | Modify | Docstring URL |
| `classifinder-mcp/pyproject.toml` | Modify | Version bump 0.1.0 → 0.1.1, bump SDK dep |
| `classifinder-site/src/components/Demo.astro` | Modify | API URL (JS + link) |
| `classifinder-site/src/components/Nav.astro` | Modify | Docs link |
| `classifinder-site/src/components/Footer.astro` | Modify | Docs link |
| `classifinder-engine/README.md` | Modify | Landing page URLs |
| `CLAUDE.md` (monorepo root) | Modify | Live URLs, DNS nameservers |
| `classifinder/CLAUDE.md` | Modify | Deployment table URLs |
| `classifinder/docs/what-was-built.md` | Modify | Deployment URLs, DNS records |
| `classifinder/docs/disclaimer.md` | Modify | If domain appears (verify) |
| `classifinder-marketing/classifinder-6-month-marketing-plan.md` | Modify | Website/API URLs |
| — | Infra | Termly policy URLs (if domain-bound) |
| — | Infra | Formspree allowed domain (if domain-locked) |

---

### Task 1: Set Up Cloudflare DNS Zone for classifinder.ai

**Files:** None (Cloudflare dashboard / CLI)

This task must be done first — everything else depends on DNS propagation.

- [ ] **Step 1: Add classifinder.ai zone to Cloudflare**

```bash
# If using Cloudflare CLI (flarectl), or do this in the Cloudflare dashboard:
# Dashboard: dash.cloudflare.com → Add a site → classifinder.ai → Free plan
```

After adding the zone, Cloudflare will assign nameservers (may differ from the .tech nameservers).

- [ ] **Step 2: Update nameservers at your domain registrar**

Go to the registrar where you purchased `classifinder.ai` and set the nameservers to the ones Cloudflare assigned. This typically takes 10-60 minutes to propagate.

- [ ] **Step 3: Wait for DNS propagation and verify**

```bash
# Check nameserver propagation
dig NS classifinder.ai +short
# Should return Cloudflare nameservers
```

- [ ] **Step 4: Add DNS records for the site (Cloudflare Workers)**

In Cloudflare dashboard for classifinder.ai zone:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| Worker route | classifinder.ai/* | classifinder-site | Proxied |
| Worker route | www.classifinder.ai/* | classifinder-site | Proxied |

Or configure via wrangler — see Task 3.

- [ ] **Step 5: Add DNS records for the API (Fly.io)**

Get the Fly.io IP addresses (same as current .tech setup):

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder
flyctl ips list -a classifinder
```

Add DNS records in Cloudflare dashboard for classifinder.ai:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | api | (IPv4 from flyctl ips list) | DNS only |
| AAAA | api | (IPv6 from flyctl ips list) | DNS only |

---

### Task 2: Add Custom Domain to Fly.io

**Files:** None (Fly.io CLI)

- [ ] **Step 1: Add the custom domain**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder
flyctl certs create api.classifinder.ai -a classifinder
```

- [ ] **Step 2: Verify TLS certificate provisioning**

```bash
flyctl certs show api.classifinder.ai -a classifinder
```

Wait until status shows the certificate is issued. This depends on DNS propagation from Task 1.

- [ ] **Step 3: Test the API on the new domain**

```bash
curl -s https://api.classifinder.ai/v1/health | python3 -m json.tool
```

Expected: `{"status": "healthy", ...}`

---

### Task 3: Update Cloudflare Workers Route for classifinder.ai

**Files:** `classifinder-site/wrangler.jsonc` (potentially)

- [ ] **Step 1: Add custom domain route for the site worker**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-site
# Add routes via Cloudflare dashboard or wrangler.jsonc
```

In the Cloudflare dashboard: Workers & Pages → classifinder-site → Settings → Domains & Routes → Add route for `classifinder.ai/*` and `www.classifinder.ai/*` on the classifinder.ai zone.

Alternatively, add to `wrangler.jsonc`:

```jsonc
{
  // ... existing config ...
  "routes": [
    { "pattern": "classifinder.ai/*", "zone_name": "classifinder.ai" },
    { "pattern": "www.classifinder.ai/*", "zone_name": "classifinder.ai" }
  ]
}
```

- [ ] **Step 2: Test the site on the new domain**

```bash
curl -sI https://classifinder.ai | head -5
```

Expected: `200 OK` with site content.

---

### Task 4: Set Up .tech → .ai Redirects

**Files:** None (Cloudflare dashboard)

Keep existing `.tech` URLs working for anyone who has bookmarked them or installed SDK versions with the old default URL.

- [ ] **Step 1: Create redirect rules in Cloudflare for classifinder.tech zone**

In Cloudflare dashboard → classifinder.tech zone → Rules → Redirect Rules:

**Rule 1 — Landing page:**
- When: Hostname equals `classifinder.tech` OR `www.classifinder.tech`
- Then: Dynamic redirect to `https://classifinder.ai${http.request.uri.path}`
- Status code: 301 (permanent)

**Rule 2 — API:**
- When: Hostname equals `api.classifinder.tech`
- Then: Dynamic redirect to `https://api.classifinder.ai${http.request.uri.path}`
- Status code: 301 (permanent)

**Important:** The API redirect means old SDK versions (with `api.classifinder.tech` hardcoded) will follow the 301 and still work. httpx follows redirects by default.

- [ ] **Step 2: Test redirects**

```bash
curl -sI https://classifinder.tech | grep -i location
# Expected: Location: https://classifinder.ai/

curl -sI https://api.classifinder.tech/v1/health | grep -i location
# Expected: Location: https://api.classifinder.ai/v1/health
```

---

### Task 5: Update classifinder-site/ Source Code

**Files:**
- Modify: `classifinder-site/src/components/Demo.astro`
- Modify: `classifinder-site/src/components/Nav.astro`
- Modify: `classifinder-site/src/components/Footer.astro`

- [ ] **Step 1: Update Demo.astro**

In `classifinder-site/src/components/Demo.astro`, replace:

```javascript
const API_URL = 'https://api.classifinder.tech/v1/demodemo';
```

With:

```javascript
const API_URL = 'https://api.classifinder.ai/v1/demodemo';
```

And replace:

```html
<a href="https://api.classifinder.tech/docs" class="btn-secondary" target="_blank">View Docs</a>
```

With:

```html
<a href="https://api.classifinder.ai/docs" class="btn-secondary" target="_blank">View Docs</a>
```

- [ ] **Step 2: Update Nav.astro**

In `classifinder-site/src/components/Nav.astro`, replace:

```html
<a href="https://api.classifinder.tech/docs" target="_blank">Docs</a>
```

With:

```html
<a href="https://api.classifinder.ai/docs" target="_blank">Docs</a>
```

- [ ] **Step 3: Update Footer.astro**

In `classifinder-site/src/components/Footer.astro`, replace:

```html
<a href="https://api.classifinder.tech/docs" target="_blank">API Docs</a>
```

With:

```html
<a href="https://api.classifinder.ai/docs" target="_blank">API Docs</a>
```

- [ ] **Step 4: Commit and push (triggers Cloudflare deploy)**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-site
git add src/components/Demo.astro src/components/Nav.astro src/components/Footer.astro
git commit -m "chore: migrate domain references from classifinder.tech to classifinder.ai"
git push origin main
```

---

### Task 6: Update classifinder-sdk/ and Publish to PyPI

**Files:**
- Modify: `classifinder-sdk/src/classifinder/_base.py:19`
- Modify: `classifinder-sdk/tests/conftest.py:6`
- Modify: `classifinder-sdk/README.md`
- Modify: `classifinder-sdk/pyproject.toml`

- [ ] **Step 1: Update DEFAULT_BASE_URL**

In `classifinder-sdk/src/classifinder/_base.py`, replace:

```python
DEFAULT_BASE_URL = "https://api.classifinder.tech"
```

With:

```python
DEFAULT_BASE_URL = "https://api.classifinder.ai"
```

- [ ] **Step 2: Update test fixture**

In `classifinder-sdk/tests/conftest.py`, replace:

```python
TEST_BASE_URL = "https://api.classifinder.tech"
```

With:

```python
TEST_BASE_URL = "https://api.classifinder.ai"
```

- [ ] **Step 3: Update README.md**

Replace all occurrences of `classifinder.tech` with `classifinder.ai` in the README.

- [ ] **Step 4: Bump version**

In `classifinder-sdk/pyproject.toml`, replace:

```toml
version = "0.1.2"
```

With:

```toml
version = "0.1.3"
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-sdk
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Expected: All tests pass.

- [ ] **Step 6: Build and publish to PyPI**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-sdk
pip install build twine
python -m build
twine upload dist/classifinder-0.1.3*
```

- [ ] **Step 7: Commit and push**

```bash
git add src/classifinder/_base.py tests/conftest.py README.md pyproject.toml
git commit -m "chore: migrate to classifinder.ai domain, bump to 0.1.3"
git push origin main
```

---

### Task 7: Update classifinder-mcp/ and Publish to PyPI

**Files:**
- Modify: `classifinder-mcp/src/classifinder_mcp/server.py:47`
- Modify: `classifinder-mcp/README.md`
- Modify: `classifinder-mcp/pyproject.toml`

- [ ] **Step 1: Update server.py docstring**

In `classifinder-mcp/src/classifinder_mcp/server.py`, replace:

```python
"Get a free key at https://classifinder.tech"
```

With:

```python
"Get a free key at https://classifinder.ai"
```

- [ ] **Step 2: Update README.md**

Replace all occurrences of `classifinder.tech` with `classifinder.ai`.

- [ ] **Step 3: Bump version and SDK dependency**

In `classifinder-mcp/pyproject.toml`, replace:

```toml
version = "0.1.0"
```

With:

```toml
version = "0.1.1"
```

And replace:

```toml
"classifinder>=0.1.2",
```

With:

```toml
"classifinder>=0.1.3",
```

- [ ] **Step 4: Build and publish to PyPI**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-mcp
python -m build
twine upload dist/classifinder_mcp-0.1.1*
```

- [ ] **Step 5: Commit and push**

```bash
git add src/classifinder_mcp/server.py README.md pyproject.toml
git commit -m "chore: migrate to classifinder.ai domain, bump to 0.1.1"
git push origin main
```

---

### Task 8: Update classifinder-engine/ Docs

**Files:**
- Modify: `classifinder-engine/README.md`

- [ ] **Step 1: Update README.md**

Replace all occurrences of `classifinder.tech` with `classifinder.ai` (2 occurrences).

- [ ] **Step 2: Commit and push**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-engine
git add README.md
git commit -m "docs: migrate domain references to classifinder.ai"
git push origin main
```

---

### Task 9: Update classifinder/ Docs and Project Files

**Files:**
- Modify: `CLAUDE.md` (monorepo root)
- Modify: `classifinder/CLAUDE.md`
- Modify: `classifinder/docs/what-was-built.md`
- Modify: `classifinder-marketing/classifinder-6-month-marketing-plan.md`

- [ ] **Step 1: Update monorepo root CLAUDE.md**

Replace all occurrences of `classifinder.tech` with `classifinder.ai` and `api.classifinder.tech` with `api.classifinder.ai`. Update the DNS nameservers line if they change.

- [ ] **Step 2: Update classifinder/CLAUDE.md**

Replace all domain references. Update deployment table URLs.

- [ ] **Step 3: Update what-was-built.md**

Replace all domain references in deployment tables and DNS records section. Update nameserver entries if they change.

- [ ] **Step 4: Update marketing plan**

In `classifinder-marketing/classifinder-6-month-marketing-plan.md`, replace:

```
**Website:** https://classifinder.tech
**API:** https://api.classifinder.tech
```

With:

```
**Website:** https://classifinder.ai
**API:** https://api.classifinder.ai
```

- [ ] **Step 5: Commit and push classifinder/**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder
git add CLAUDE.md docs/what-was-built.md
git commit -m "docs: migrate domain references to classifinder.ai"
git push origin main
```

---

### Task 10: Update External Services

**Files:** None (dashboards / web UIs)

- [ ] **Step 1: Termly**

Check if the Termly privacy policy and terms of service reference `classifinder.tech` in their URLs or content. Update the site URL in Termly dashboard settings if so.

- [ ] **Step 2: Formspree**

If the early access form on the landing page is domain-locked to `classifinder.tech`, add `classifinder.ai` as an allowed domain in Formspree settings.

- [ ] **Step 3: PyPI project descriptions**

Verify that the PyPI pages for `classifinder` and `classifinder-mcp` show the updated README with `.ai` URLs after the new versions are published.

---

### Task 11: Verification

- [ ] **Step 1: Test new domains**

```bash
# Landing page
curl -sI https://classifinder.ai | head -3

# API health
curl -s https://api.classifinder.ai/v1/health | python3 -m json.tool

# API docs
curl -sI https://api.classifinder.ai/docs | head -3
```

- [ ] **Step 2: Test .tech redirects**

```bash
# Landing page redirect
curl -sI https://classifinder.tech | grep -i location
# Expected: 301 → https://classifinder.ai/

# API redirect
curl -sI https://api.classifinder.tech/v1/health | grep -i location
# Expected: 301 → https://api.classifinder.ai/v1/health
```

- [ ] **Step 3: Test SDK with new default**

```bash
pip install classifinder==0.1.3
python -c "from classifinder import ClassiFinder; print(ClassiFinder._default_base_url)"
# Or just verify the import works
```

- [ ] **Step 4: Test old SDK still works via redirect**

```bash
pip install classifinder==0.1.2
python -c "
from classifinder import ClassiFinder
c = ClassiFinder(api_key='ss_test_key')
# The old default URL should 301 → new URL, httpx follows redirects
"
```

---

## Execution Order

```
Task 1: DNS zone setup          ← START HERE, blocks everything
Task 2: Fly.io custom domain    ← needs DNS propagation
Task 3: Workers route           ← needs DNS propagation
Task 4: .tech redirects         ← after new domains confirmed working
Task 5: Site code updates       ← after new domains confirmed working
Task 6: SDK update + PyPI       ← after api.classifinder.ai is live
Task 7: MCP update + PyPI       ← after SDK 0.1.3 is on PyPI
Task 8: Engine docs             ← anytime
Task 9: Project docs            ← anytime
Task 10: External services      ← after all domains are live
Task 11: Verification           ← last
```

Tasks 8-9 can run in parallel with 5-7. The critical path is: DNS (1) → Fly.io cert (2) + Workers route (3) → redirects (4) → SDK release (6) → MCP release (7) → verify (11).
