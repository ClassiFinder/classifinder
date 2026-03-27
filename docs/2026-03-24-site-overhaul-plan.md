# ClassiFinder Site Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild classifinder.tech from monolithic HTML to an Astro site with noir visual identity, dark/light secret-reveal mechanic, interactive demo, and self-serve key creation.

**Architecture:** Astro static site with vanilla JS for two interactive components (Demo and GetKey). CSS custom properties handle dark/light theming. Deployed via existing GitHub Actions → wrangler deploy pipeline.

**Tech Stack:** Astro 5.x, vanilla JS, CSS custom properties, Google Fonts (Playfair Display, Source Serif 4, DM Mono)

**Spec:** `docs/superpowers/specs/2026-03-24-site-overhaul-design.md`

**Mockup reference:** `.superpowers/brainstorm/95462-1774400472/noir-concept.html`

---

## File Map

| File | Responsibility | Task |
|------|---------------|------|
| `package.json` | Astro dependencies, build script | 1 |
| `astro.config.mjs` | Astro config (static output) | 1 |
| `tsconfig.json` | TypeScript config for Astro | 1 |
| `build.sh` | Updated: runs `npm run build` | 1 |
| `.github/workflows/deploy.yml` | Updated: adds `npm ci` step | 1 |
| `src/styles/global.css` | CSS custom properties, dark/light themes, base styles, responsive breakpoints | 2 |
| `src/layouts/BaseLayout.astro` | HTML shell, font loading, meta tags, theme script, hidden secrets layer, dog bg | 3 |
| `src/components/SectionDivider.astro` | Noir ornament divider (`• • •`) | 3 |
| `src/components/ThemeToggle.astro` | Dark/Light? toggle button | 3 |
| `src/components/HiddenSecrets.astro` | Background watermark secrets layer | 3 |
| `src/components/Nav.astro` | Fixed top nav with anchor links, patterns link, docs link, CTA | 4 |
| `src/components/Footer.astro` | Footer with links and disclaimer | 4 |
| `src/components/Hero.astro` | Hero section: badge, headline, CTAs, stats | 5 |
| `src/components/Demo.astro` | Interactive demo with client-side JS | 6 |
| `src/components/HowItWorks.astro` | Install/Scan/Ship cards + LangChain example | 7 |
| `src/components/WhyClassiFinder.astro` | Comparison table section | 7 |
| `src/components/Trust.astro` | 2x2 trust cards grid | 7 |
| `src/components/Pricing.astro` | Three-column pricing grid | 7 |
| `src/components/GetKey.astro` | Key creation form with client-side JS | 8 |
| `src/pages/index.astro` | Landing page composing all components | 9 |
| `src/pages/patterns.astro` | Pattern library page | 10 |
| `src/pages/privacy-policy.astro` | Privacy policy page | 11 |
| `src/pages/terms-of-service.astro` | Terms of service page | 11 |
| `public/assets/classifinder_dog4.jpg` | Dog mascot image | 3 |

---

### Task 1: Scaffold Astro project and update pipeline

**Files:**
- Create: `package.json`, `astro.config.mjs`, `tsconfig.json`
- Modify: `build.sh`, `.github/workflows/deploy.yml`, `.gitignore`

- [ ] **Step 1: Initialize Astro project**

```bash
cd /Users/thomasparas/Documents/ClassiFinder/classifinder-site
npm create astro@latest . -- --template minimal --no-install --no-git --typescript strict
```

If prompted about overwriting, accept for `package.json`, `tsconfig.json`, `astro.config.mjs`. Do NOT overwrite `.gitignore`.

- [ ] **Step 2: Configure Astro for static output**

Write `astro.config.mjs`:

```js
import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  build: {
    format: 'directory',
  },
});
```

- [ ] **Step 3: Install dependencies**

```bash
npm install
```

- [ ] **Step 4: Update build.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

npm run build

echo "Build complete → dist/"
```

- [ ] **Step 5: Update .github/workflows/deploy.yml**

Add Node.js setup and `npm ci` before the build step:

```yaml
name: Deploy to Cloudflare Workers

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: bash build.sh

      - name: Deploy to Cloudflare
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: "4"
          command: deploy
```

- [ ] **Step 6: Update .gitignore**

Append Astro-specific entries:

```
dist/
node_modules/
.astro/
.superpowers/
```

- [ ] **Step 7: Create src directory structure**

```bash
mkdir -p src/layouts src/components src/pages src/styles public/assets
```

- [ ] **Step 8: Copy dog mascot to public/assets**

```bash
cp assets/classifinder_dog4.jpg public/assets/classifinder_dog4.jpg
```

- [ ] **Step 9: Create a minimal index page and verify build**

Write `src/pages/index.astro`:

```astro
---
---
<html lang="en">
  <head><title>ClassiFinder</title></head>
  <body><h1>ClassiFinder</h1></body>
</html>
```

Run:

```bash
npm run build
ls dist/index.html
```

Expected: `dist/index.html` exists.

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json astro.config.mjs tsconfig.json build.sh .github/workflows/deploy.yml .gitignore src/ public/
git commit -m "feat: scaffold Astro project and update build pipeline"
```

---

### Task 2: Global CSS — theme system and base styles

**Files:**
- Create: `src/styles/global.css`

- [ ] **Step 1: Write global.css with dark/light theme variables and base styles**

```css
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Playfair+Display:ital,wght@0,400;0,700;0,900;1,400&family=Source+Serif+4:ital,wght@0,400;0,600;0,700;1,400&display=swap');

:root {
  --bg: #0a0a0c;
  --bg-raised: #111116;
  --bg-code: #16161d;
  --border: #222230;
  --border-bright: #333345;
  --text: #c8c8d4;
  --text-dim: #6e6e82;
  --text-bright: #eeeef4;
  --accent: #5cdb5c;
  --accent-dim: #2a5c2a;
  --red: #e85454;
  --orange: #e8a054;
  --blue: #5496e8;
  --hidden-secrets-opacity: 0;
  --dog-opacity: 0.06;
  --mascot-filter: invert(1) brightness(0.7);
}

[data-theme="light"] {
  --bg: #f4f0e8;
  --bg-raised: #ebe7dd;
  --bg-code: #e2ddd2;
  --border: #c8c2b4;
  --border-bright: #a89e8e;
  --text: #3a3630;
  --text-dim: #7a7468;
  --text-bright: #1a1814;
  --accent: #2d7a2d;
  --accent-dim: #d4e8d4;
  --red: #b83030;
  --orange: #9a6020;
  --blue: #2a5a9e;
  --hidden-secrets-opacity: 1;
  --dog-opacity: 0.08;
  --mascot-filter: sepia(0.3) brightness(0.9);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }

body {
  font-family: 'Source Serif 4', Georgia, serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
  transition: background 0.5s, color 0.4s;
}

::selection {
  background: var(--accent-dim);
  color: var(--accent);
}

section { max-width: 860px; margin: 0 auto; padding: 0 2rem; }

h1, h2 {
  font-family: 'Playfair Display', serif;
  color: var(--text-bright);
  transition: color 0.4s;
}

h1 {
  font-size: clamp(2.4rem, 5vw, 3.6rem);
  font-weight: 900;
  line-height: 1.1;
  letter-spacing: -0.02em;
}

h1 em { font-style: italic; color: var(--accent); }

h2 {
  font-size: 1.8rem;
  font-weight: 700;
  line-height: 1.2;
  margin-bottom: 0.5rem;
}

/* Section labels — noir case-file style */
.section-label {
  font-family: 'DM Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.5rem;
  transition: color 0.4s;
}

.section-intro {
  color: var(--text);
  margin-bottom: 2rem;
  max-width: 560px;
  transition: color 0.4s;
}

.section-space { padding: 4rem 0; }

/* Buttons */
.btn-primary {
  display: inline-block;
  background: var(--accent);
  color: var(--bg);
  padding: 0.65rem 1.5rem;
  border-radius: 4px;
  font-family: 'DM Mono', monospace;
  font-size: 0.85rem;
  font-weight: 500;
  text-decoration: none;
  border: none;
  cursor: pointer;
  transition: opacity 0.15s;
}
.btn-primary:hover { opacity: 0.85; }

.btn-secondary {
  display: inline-block;
  border: 1px solid var(--border-bright);
  color: var(--text);
  padding: 0.65rem 1.5rem;
  border-radius: 4px;
  font-family: 'DM Mono', monospace;
  font-size: 0.85rem;
  text-decoration: none;
  background: transparent;
  transition: all 0.3s;
}
.btn-secondary:hover { border-color: var(--text-dim); color: var(--text-bright); }

/* Code blocks */
.code-block {
  background: var(--bg-code);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  transition: all 0.4s;
}
.code-header {
  font-family: 'DM Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-dim);
  padding: 0.5rem 1rem;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  display: flex;
  justify-content: space-between;
  transition: all 0.4s;
}
.code-body {
  padding: 1rem;
  font-family: 'DM Mono', monospace;
  font-size: 0.8rem;
  line-height: 1.8;
  color: var(--text);
  white-space: pre;
  overflow-x: auto;
  transition: color 0.4s;
}
.kw { color: var(--blue); }
.str { color: var(--accent); }
.comment { color: var(--text-dim); }
.key { color: var(--orange); }
.num { color: var(--orange); }
.sev { color: var(--red); }

/* Noir decorative divider */
.rule {
  border: none;
  height: 1px;
  background: var(--border);
  margin: 0;
  transition: background 0.4s;
}
.ornament {
  text-align: center;
  color: var(--border-bright);
  font-size: 1.2rem;
  padding: 1rem 0;
  letter-spacing: 0.5rem;
  transition: color 0.4s;
}

/* Responsive */
@media (max-width: 700px) {
  .hero-stats { flex-direction: column; gap: 1.5rem; }
  .demo-panels { grid-template-columns: 1fr; }
  .steps-row { flex-direction: column; }
  .compare-table-wrap { overflow-x: auto; }
  .trust-grid { grid-template-columns: 1fr; }
  .pricing-grid { grid-template-columns: 1fr; }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/styles/global.css
git commit -m "feat: add global CSS with dark/light theme system"
```

---

### Task 3: Base layout, theme toggle, hidden secrets, mascot

**Files:**
- Create: `src/layouts/BaseLayout.astro`, `src/components/ThemeToggle.astro`, `src/components/HiddenSecrets.astro`, `src/components/SectionDivider.astro`

- [ ] **Step 1: Write BaseLayout.astro**

The HTML shell that every page uses. Includes:
- `<html lang="en">`, proper `<title>` and `<meta name="description">`
- Google Fonts preconnect + stylesheet link
- Global CSS import
- `<slot />` for page content
- HiddenSecrets component
- Dog mascot `<img>` with `alt=""`, `aria-hidden="true"`, themed opacity/filter
- Inline `<script>` for theme initialization (check localStorage before paint to prevent flash)

```astro
---
import '../styles/global.css';
import HiddenSecrets from '../components/HiddenSecrets.astro';

interface Props {
  title?: string;
  description?: string;
}

const {
  title = 'ClassiFinder — Secret scanning for the AI era',
  description = 'A stateless API that scans and redacts credentials from text before it reaches your LLM, your logs, or your users.',
} = Astro.props;
---
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <meta name="description" content={description}>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Playfair+Display:ital,wght@0,400;0,700;0,900;1,400&family=Source+Serif+4:ital,wght@0,400;0,600;0,700;1,400&display=swap" rel="stylesheet">
  <script is:inline>
    (function() {
      const theme = localStorage.getItem('theme');
      if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
    })();
  </script>
</head>
<body>
  <HiddenSecrets />
  <img
    src="/assets/classifinder_dog4.jpg"
    alt=""
    aria-hidden="true"
    style="position:fixed;bottom:-60px;right:-40px;width:500px;opacity:var(--dog-opacity);filter:var(--mascot-filter);pointer-events:none;z-index:0;transition:opacity 0.5s,filter 0.5s;"
  >
  <div style="position:relative;z-index:1;">
    <slot />
  </div>
</body>
</html>
```

- [ ] **Step 2: Write HiddenSecrets.astro**

Fixed-position layer of fake secrets, only visible in light mode. Must have `aria-hidden="true"`.

```astro
---
const secrets = [
  { text: 'AKIAIOSFODNN7EXAMPLE', top: '8%', left: '5%', rot: '-3deg' },
  { text: 'postgres://admin:p4ssw0rd@prod-db:5432/users', top: '15%', right: '8%', rot: '2deg' },
  { text: 'sk_live_51H7bKLkdFJH38djfhKSDJ', top: '25%', left: '12%', rot: '-1deg' },
  { text: 'ghp_ABCDEFghijklMNOP1234567890abcdef', top: '35%', right: '15%', rot: '4deg' },
  { text: '-----BEGIN RSA PRIVATE KEY-----', top: '45%', left: '3%', rot: '-2deg' },
  { text: 'STRIPE_SECRET=sk_live_rk38Djfh2ksjdhf', top: '55%', right: '5%', rot: '1deg' },
  { text: 'mongodb+srv://root:hunter2@cluster0.abc123.net', top: '65%', left: '18%', rot: '-4deg' },
  { text: 'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG', top: '72%', right: '12%', rot: '2deg' },
  { text: 'ANTHROPIC_API_KEY=sk-ant-api03-example', top: '82%', left: '8%', rot: '-1deg' },
  { text: 'OPENAI_API_KEY=sk-proj-abc123def456', top: '78%', left: '50%', rot: '-3deg' },
  { text: 'SENDGRID_API_KEY=SG.xxxxxxxxx.yyyyyy', top: '18%', left: '55%', rot: '-5deg' },
  { text: 'DATABASE_URL=postgres://app:secret@rds.aws:5432', top: '48%', left: '40%', rot: '1deg' },
  { text: 'mysql://deploy:s3cur3_pw@10.0.0.5:3306', top: '90%', right: '20%', rot: '3deg' },
];
---
<div
  aria-hidden="true"
  style="position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:var(--hidden-secrets-opacity);transition:opacity 0.8s ease;overflow:hidden;"
>
  {secrets.map((s) => (
    <span style={`position:absolute;font-family:'DM Mono',monospace;font-size:11px;color:var(--text-dim);opacity:0.18;white-space:nowrap;top:${s.top};${s.left ? `left:${s.left}` : `right:${s.right}`};transform:rotate(${s.rot});`}>
      {s.text}
    </span>
  ))}
</div>
<div
  style="position:fixed;bottom:20px;left:20px;font-family:'DM Mono',monospace;font-size:0.65rem;color:var(--text-dim);opacity:0;transition:opacity 0.8s;z-index:50;pointer-events:none;"
  class="reveal-hint"
>
  Look closely — secrets are hiding in the background
</div>
<style>
  [data-theme="light"] .reveal-hint { opacity: 1; }
</style>
```

- [ ] **Step 3: Write ThemeToggle.astro**

```astro
---
---
<div style="display:flex;align-items:center;gap:6px;">
  <span class="toggle-label">Dark</span>
  <button class="theme-toggle" aria-label="Toggle theme"></button>
  <span class="toggle-label">Light?</span>
</div>

<style>
  .toggle-label {
    font-family: 'DM Mono', monospace;
    font-size: 0.6rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .theme-toggle {
    width: 36px;
    height: 20px;
    background: var(--border-bright);
    border-radius: 10px;
    position: relative;
    cursor: pointer;
    transition: background 0.3s;
    border: none;
    outline: none;
  }
  .theme-toggle:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .theme-toggle::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    background: var(--text-bright);
    border-radius: 50%;
    transition: transform 0.3s;
  }
  :global([data-theme="light"]) .theme-toggle::after {
    transform: translateX(16px);
  }
</style>

<script>
  const btn = document.querySelector('.theme-toggle');
  btn?.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.removeItem('theme');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      localStorage.setItem('theme', 'light');
    }
  });
</script>
```

- [ ] **Step 4: Write SectionDivider.astro**

```astro
---
---
<hr class="rule">
<div class="ornament">&bull; &bull; &bull;</div>
<hr class="rule">
```

- [ ] **Step 5: Verify build**

Update `src/pages/index.astro` to use the layout:

```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
import SectionDivider from '../components/SectionDivider.astro';
---
<BaseLayout>
  <h1>ClassiFinder</h1>
  <SectionDivider />
  <p>Layout test</p>
</BaseLayout>
```

Run: `npm run build && ls dist/index.html`

Expected: builds successfully.

- [ ] **Step 6: Commit**

```bash
git add src/layouts/ src/components/ThemeToggle.astro src/components/HiddenSecrets.astro src/components/SectionDivider.astro src/pages/index.astro public/assets/
git commit -m "feat: add base layout with theme toggle, hidden secrets, and mascot"
```

---

### Task 4: Nav and Footer components

**Files:**
- Create: `src/components/Nav.astro`, `src/components/Footer.astro`

- [ ] **Step 1: Write Nav.astro**

Fixed top nav with: logo (Classi*Finder*), anchor links (Try It, How It Works, Why Us, Patterns, Pricing), external Docs link, ThemeToggle, and CTA button.

Refer to the mockup (`noir-concept.html` lines in `<nav>`) for exact structure. Key details:
- Logo: `Classi` in Playfair Display 900 + `Finder` in Playfair Display 400 italic green
- Nav links: DM Mono, uppercase, 0.75rem
- CTA: green border, links to `#get-key`
- Background: `color-mix(in srgb, var(--bg) 85%, transparent)` with `backdrop-filter: blur(12px)`
- Mobile (≤700px): hide nav links by default, show a `<button class="nav-burger" aria-label="Menu">` (three-line icon via CSS pseudo-elements). On click, toggle a `nav-open` class on the `<nav>` element. When `nav-open` is set, show the links as a vertical dropdown below the nav bar. JS: `document.querySelector('.nav-burger')?.addEventListener('click', () => document.querySelector('nav')?.classList.toggle('nav-open'))`. CSS: `.nav-burger { display: none }` on desktop, `@media (max-width: 700px) { .nav-links { display: none } .nav-burger { display: block } .nav-open .nav-links { display: flex; flex-direction: column; } }`

Import and include `ThemeToggle` component.

- [ ] **Step 2: Write Footer.astro**

Footer with:
- "ClassiFinder · Secret scanning for the AI era"
- Links: API Docs (external), GitHub (classifinder-engine repo), Patterns (/patterns), Privacy (/privacy-policy), Terms (/terms-of-service)
- Disclaimer text — read `../classifinder/docs/disclaimer.md` and include the brief version inline

Key details:
- Border-top divider
- Centered, small text (0.75rem)
- DM Mono for links

- [ ] **Step 3: Update index.astro to include Nav and Footer**

```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
import Nav from '../components/Nav.astro';
import Footer from '../components/Footer.astro';
import SectionDivider from '../components/SectionDivider.astro';
---
<BaseLayout>
  <Nav />
  <section style="padding-top:10rem;"><h1>ClassiFinder</h1></section>
  <SectionDivider />
  <Footer />
</BaseLayout>
```

- [ ] **Step 4: Verify build**

Run: `npm run build`

Expected: builds successfully.

- [ ] **Step 5: Commit**

```bash
git add src/components/Nav.astro src/components/Footer.astro src/pages/index.astro
git commit -m "feat: add Nav and Footer components"
```

---

### Task 5: Hero component

**Files:**
- Create: `src/components/Hero.astro`

- [ ] **Step 1: Write Hero.astro**

Refer to spec Section 1 and mockup. Content:
- Badge: "Now in Early Access" (DM Mono, green on green-dim bg)
- Headline: `The case of the <em>leaked secret</em>` (Playfair Display 900, em in green italic)
- Subheadline (Source Serif 4)
- Two CTAs: "Try the Demo" (`btn-primary`, href `#try-it`) + "View Docs" (`btn-secondary`, href to external docs)
- Four stats in a flex row with border-top: `50` / `<5ms` / `0 bytes` / `open source`
- Stats use DM Mono for values, small text for labels
- Add responsive class `hero-stats` for mobile stacking

- [ ] **Step 2: Wire into index.astro**

Add Hero between Nav and first SectionDivider.

- [ ] **Step 3: Verify build**

Run: `npm run build`

- [ ] **Step 4: Commit**

```bash
git add src/components/Hero.astro src/pages/index.astro
git commit -m "feat: add Hero section"
```

---

### Task 6: Interactive Demo component

**Files:**
- Create: `src/components/Demo.astro`

- [ ] **Step 1: Write Demo.astro**

This is one of two components with client-side JS. Refer to spec Section 2.

Structure:
- Section label: "The Evidence"
- Headline: "Paste text. Watch secrets vanish."
- Subtext about real-time scanning
- Two-panel grid (`demo-panels` class for responsive):
  - Left: `<textarea>` pre-filled with example secrets, styled as code block
  - Right: output div styled as code block with green accent border, shows pre-computed result initially
- "Scan" button below the textarea
- Footer line: `POST /v1/redact · 50 patterns · more added every week`

Client-side `<script>`:
- On "Scan" button click:
  1. Show "Scanning..." in output panel
  2. `fetch('https://api.classifinder.tech/v1/redact', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': DEMO_KEY }, body: JSON.stringify({ text: textarea.value }) })`
  3. On success: display `redacted_text` in output, update finding count and response time
  4. On error: display "API unavailable — try again" in output
- Initial state: pre-computed example output (no API call on page load)
- Use a placeholder `DEMO_KEY` constant — will be replaced when demo key strategy is decided

- [ ] **Step 2: Wire into index.astro**

Add Demo after Hero + SectionDivider.

- [ ] **Step 3: Verify build**

Run: `npm run build`

- [ ] **Step 4: Commit**

```bash
git add src/components/Demo.astro src/pages/index.astro
git commit -m "feat: add interactive Demo section"
```

---

### Task 7: Static content sections — HowItWorks, WhyClassiFinder, Trust, Pricing

**Files:**
- Create: `src/components/HowItWorks.astro`, `src/components/WhyClassiFinder.astro`, `src/components/Trust.astro`, `src/components/Pricing.astro`

- [ ] **Step 1: Write HowItWorks.astro**

Refer to spec Section 3. Section label: "The Method". Three code cards in a flex row (`steps-row` class for responsive) + full LangChain code block below. Header label: "Available now".

- [ ] **Step 2: Write WhyClassiFinder.astro**

Refer to spec Section 4. Section label: "The Suspects". Comparison table in a scrollable wrapper (`compare-table-wrap` class for responsive). ClassiFinder column cells use `color: var(--accent)`. Other cells use `var(--text-dim)` or `var(--red)`.

- [ ] **Step 3: Write Trust.astro**

Refer to spec Section 5. Section label: "The Proof". 2x2 grid (`trust-grid` class for responsive). Four cards with Playfair Display h3 headings. Open-source card links to `https://github.com/ThomasParas/classifinder-engine`.

- [ ] **Step 4: Write Pricing.astro**

Refer to spec Section 6. Section label: "The Fee". Three-column grid (`pricing-grid` class for responsive). Free card has green accent border. Starter and Pro have `opacity: 0.5` and show "Coming Soon".

- [ ] **Step 5: Wire all four into index.astro**

Add in order after Demo: SectionDivider, HowItWorks, SectionDivider, WhyClassiFinder, SectionDivider, Trust, SectionDivider, Pricing.

- [ ] **Step 6: Verify build**

Run: `npm run build`

- [ ] **Step 7: Commit**

```bash
git add src/components/HowItWorks.astro src/components/WhyClassiFinder.astro src/components/Trust.astro src/components/Pricing.astro src/pages/index.astro
git commit -m "feat: add HowItWorks, WhyClassiFinder, Trust, and Pricing sections"
```

---

### Task 8: GetKey form component

**Files:**
- Create: `src/components/GetKey.astro`

- [ ] **Step 1: Write GetKey.astro**

Second component with client-side JS. Refer to spec Section 7.

Structure:
- Centered section, no section label
- Headline: "Get your API key"
- Subtext: "Start scanning in under a minute. Free forever for small projects."
- Form wrapper (max-width 420px, centered):
  - Email input (required), DM Mono label
  - Checkbox: "Email me about new features and updates" (unchecked by default)
  - Submit button: "Create API Key" (btn-primary, full width)
- Success state: hide form, show API key in a code-styled box with copy button and warning "Save this — you won't see it again"
- Error state: show error message inline below form

Client-side `<script>`:
- On form submit (prevent default):
  1. Disable button, show "Creating..."
  2. Try `fetch('https://api.classifinder.tech/v1/keys/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, subscribe }) })`
  3. On success (key returned): swap to success state
  4. On error / 4xx / 5xx: show error message
  5. Fallback: if endpoint returns network error, fall back to Formspree POST and show "We'll email your key shortly"
- Copy button: `navigator.clipboard.writeText(apiKey)`

- [ ] **Step 2: Wire into index.astro**

Add GetKey after Pricing + SectionDivider.

- [ ] **Step 3: Verify build**

Run: `npm run build`

- [ ] **Step 4: Commit**

```bash
git add src/components/GetKey.astro src/pages/index.astro
git commit -m "feat: add GetKey form with API key creation and Formspree fallback"
```

---

### Task 9: Assemble landing page (index.astro)

**Files:**
- Modify: `src/pages/index.astro`

- [ ] **Step 1: Write the final index.astro**

Compose all components in the correct order:

```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
import Nav from '../components/Nav.astro';
import Hero from '../components/Hero.astro';
import SectionDivider from '../components/SectionDivider.astro';
import Demo from '../components/Demo.astro';
import HowItWorks from '../components/HowItWorks.astro';
import WhyClassiFinder from '../components/WhyClassiFinder.astro';
import Trust from '../components/Trust.astro';
import Pricing from '../components/Pricing.astro';
import GetKey from '../components/GetKey.astro';
import Footer from '../components/Footer.astro';
---
<BaseLayout>
  <Nav />
  <Hero />
  <SectionDivider />
  <Demo />
  <SectionDivider />
  <HowItWorks />
  <SectionDivider />
  <WhyClassiFinder />
  <SectionDivider />
  <Trust />
  <SectionDivider />
  <Pricing />
  <SectionDivider />
  <GetKey />
  <Footer />
</BaseLayout>
```

- [ ] **Step 2: Verify full build and preview**

```bash
npm run build
npx astro preview
```

Open in browser, verify:
- All sections render in correct order
- Dark/light toggle works and persists across refresh
- Hidden secrets appear in light mode
- Dog mascot visible as subtle background
- Responsive: resize to ≤700px, verify all grids stack
- Demo scan button shows "API unavailable — try again" gracefully (expected with placeholder demo key)
- GetKey form submits and falls back to Formspree if `/v1/keys/create` is not live
- Nav anchor links scroll to correct sections

- [ ] **Step 3: Commit**

```bash
git add src/pages/index.astro
git commit -m "feat: assemble complete landing page"
```

---

### Task 10: Patterns page

**Files:**
- Create: `src/pages/patterns.astro`

- [ ] **Step 1: Write patterns.astro**

Read the pattern library from `../classifinder/docs/pattern-library.md` for content reference. Hardcode the pattern data in the page (simpler than build-time fetch for now).

Structure:
- Uses `BaseLayout` with title "ClassiFinder — Detection Patterns"
- Nav and Footer
- Headline: "Detection Patterns"
- Subtext: "50 secret types across 7 categories. More added every week."
- For each category: `<h3>` heading + list of patterns
- Each pattern: name (DM Mono), description, masked example in a small code block
- Categories: Cloud Provider Keys, Payment & Financial, Database & Connection Strings, Communication & Messaging, Private Keys & Certificates, CI/CD & DevOps, AI Provider Keys

Use simple semantic HTML — `<section>` per category, `<dl>` or `<div>` per pattern.

- [ ] **Step 2: Verify build and navigation**

```bash
npm run build
ls dist/patterns/index.html
```

Expected: page exists at `/patterns`.

- [ ] **Step 3: Commit**

```bash
git add src/pages/patterns.astro
git commit -m "feat: add patterns page with 50 detection patterns"
```

---

### Task 11: Legal pages (privacy policy, terms of service)

**Files:**
- Create: `src/pages/privacy-policy.astro`, `src/pages/terms-of-service.astro`

- [ ] **Step 1: Write privacy-policy.astro**

Wrap the existing `privacy-policy.html` content in BaseLayout. Read the existing file, extract the `<body>` content, and paste it into the Astro page. Include Nav and Footer.

- [ ] **Step 2: Write terms-of-service.astro**

Same approach with `terms-of-service.html`. The file exists at the repo root as `terms-of-service.html` — extract its body content into the Astro page.

- [ ] **Step 3: Verify build**

```bash
npm run build
ls dist/privacy-policy/index.html dist/terms-of-service/index.html
```

Expected: both exist.

- [ ] **Step 4: Commit**

```bash
git add src/pages/privacy-policy.astro src/pages/terms-of-service.astro
git commit -m "feat: add privacy policy and terms of service pages"
```

---

### Task 12: Clean up old files and update CLAUDE.md

**Files:**
- Delete: `index.html` (old monolithic file, now replaced by Astro)
- Delete: `privacy-policy.html`, `terms-of-service.html` (migrated to Astro pages)
- Modify: `CLAUDE.md`

- [ ] **Step 1: Remove old HTML files**

```bash
git rm index.html privacy-policy.html terms-of-service.html
```

- [ ] **Step 2: Update CLAUDE.md**

Update deployment section to reflect:
- Site is now built with Astro (`npm run build`)
- Deployed via GitHub Actions → `wrangler deploy` (not Cloudflare Pages auto-deploy)
- Update file structure description to match new Astro layout
- Update the design system section to reflect noir identity, new fonts, new logo treatment

- [ ] **Step 3: Verify full build from clean state**

```bash
rm -rf dist node_modules
npm ci
npm run build
ls dist/
```

Expected: `dist/` contains `index.html`, `patterns/index.html`, `privacy-policy/index.html`, `terms-of-service/index.html`, and `assets/classifinder_dog4.jpg`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove old HTML files and update CLAUDE.md for Astro migration"
```

---

### Task 13: Deploy and verify

- [ ] **Step 1: Push to main**

```bash
git push origin main
```

- [ ] **Step 2: Watch the deploy**

```bash
gh run watch
```

Expected: GitHub Actions succeeds — npm ci, build, wrangler deploy all pass.

- [ ] **Step 3: Verify live site**

Open https://classifinder.tech and verify:
- All sections render correctly
- Dark/light toggle works, hidden secrets appear in light mode
- Dog mascot visible in background
- Nav links work (anchor links + /patterns)
- /patterns page loads
- /privacy-policy and /terms-of-service pages load
- Footer links work
- Demo section renders (API call may fail without demo key — that's expected)
- GetKey form renders (may fall back to Formspree — that's expected)

- [ ] **Step 4: Done**

Site overhaul complete. Future work: demo API key, Open Graph meta tags, favicon.
