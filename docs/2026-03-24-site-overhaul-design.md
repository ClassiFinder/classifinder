# ClassiFinder Site Overhaul — Design Spec

**Date:** 2026-03-24
**Status:** Draft
**Mockup:** `.superpowers/brainstorm/95462-1774400472/noir-concept.html`

## Summary

Ground-up rebuild of classifinder.tech from a single monolithic HTML file to an Astro-based site with a noir/pulp fiction visual identity, dark/light mode with a hidden-secrets reveal mechanic, and a conversion flow that leads visitors from an interactive demo to self-serve API key creation.

## Goals

1. Rebuild the site using Astro for component-based architecture and proper routing
2. Establish a distinctive noir visual identity that separates ClassiFinder from every other dev tool landing page
3. Convert visitors through a Demo → Key Form funnel on a single-scroll landing page
4. Address all launch-blocking content fixes from `todo.md`
5. Deploy via the existing GitHub Actions → Cloudflare Workers pipeline (`wrangler deploy`). Note: the site was migrated from Cloudflare Pages auto-deploy to GitHub Actions + `wrangler deploy` earlier in this session. The `classifinder-site/CLAUDE.md` should be updated to reflect this.

## Non-Goals

- Blog or changelog (future)
- Interactive playground on a separate `/demo` page (the demo is embedded on the landing page)
- Paid tier pricing details (Starter and Pro remain "Coming Soon")
- Analytics integration
- Server-side rendering or dynamic content beyond the demo's API calls

---

## Site Architecture

**The README approach:** A single-scroll landing page that tells the full story, plus separate pages for deeper content and legal.

### Pages

| Route | Purpose |
|-------|---------|
| `/` | Landing page — full narrative scroll with all sections |
| `/patterns` | Detection pattern library — 50 patterns grouped by category |
| `/privacy-policy` | Privacy policy (existing `privacy-policy.html`, migrated to Astro layout) |
| `/terms-of-service` | Terms of service (content from Termly — if not yet generated, page shows placeholder with "Coming soon") |

### Navigation

Fixed top nav with anchor links to landing page sections + links to Patterns and external Docs:

```
ClassiFinder    Try It  How It Works  Why Us  Patterns  Pricing  Docs  [Dark/Light?]  [Get API Key]
```

- "Patterns" links to `/patterns`
- "Docs" links to `https://api.classifinder.tech/docs` (external)
- "Get API Key" is the primary CTA, anchors to `#get-key`
- Dark/Light toggle in the nav bar with labels "Dark" and "Light?" (question mark teases the reveal)

---

## Visual Identity

### Art Direction: Noir / Pulp Fiction

Inspired by 1930s–1950s black-and-white pulp fiction, detective novels, and noir film. The site should feel like a case file from a private detective's office — not a typical SaaS landing page.

### Typography

| Role | Font | Weight | Usage |
|------|------|--------|-------|
| Headlines, logo "Classi" | Playfair Display | 900 (Black) | Section titles, hero headline |
| Logo "Finder" | Playfair Display | 400 Italic | Green accent color, italic |
| Body text | Source Serif 4 | 400, 600 | Paragraphs, descriptions |
| Code, labels, stats, buttons | DM Mono | 400, 500 | Code blocks, section labels, CTAs, nav links |

All loaded from Google Fonts.

### Logo

**Classi*Finder*** — "Classi" in Playfair Display Black (white/dark text), "Finder" in Playfair Display Italic (green accent). No dot, no separator.

### Color System

**Dark mode (default):**

| Variable | Hex | Usage |
|----------|-----|-------|
| `--bg` | `#0a0a0c` | Page background |
| `--bg-raised` | `#111116` | Cards |
| `--bg-code` | `#16161d` | Code blocks, form inputs |
| `--border` | `#222230` | Default borders |
| `--border-bright` | `#333345` | Emphasized borders |
| `--text` | `#c8c8d4` | Body text |
| `--text-dim` | `#6e6e82` | Secondary text |
| `--text-bright` | `#eeeef4` | Headings |
| `--accent` | `#5cdb5c` | Green accent (CTAs, logo "Finder", highlights) |
| `--accent-dim` | `#2a5c2a` | Accent backgrounds |
| `--red` | `#e85454` | Severity indicators |
| `--orange` | `#e8a054` | JSON keys, numbers |
| `--blue` | `#5496e8` | Code keywords |

**Light mode (revealed case file):**

| Variable | Hex | Usage |
|----------|-----|-------|
| `--bg` | `#f4f0e8` | Aged parchment/cream |
| `--bg-raised` | `#ebe7dd` | Cards |
| `--bg-code` | `#e2ddd2` | Code blocks |
| `--border` | `#c8c2b4` | Borders |
| `--border-bright` | `#a89e8e` | Emphasized borders |
| `--text` | `#3a3630` | Body text (dark ink) |
| `--text-dim` | `#7a7468` | Secondary text |
| `--text-bright` | `#1a1814` | Headings |
| `--accent` | `#2d7a2d` | Darker green for readability |
| `--accent-dim` | `#d4e8d4` | Accent backgrounds |
| `--red` | `#b83030` | Severity indicators |
| `--orange` | `#9a6020` | JSON keys, numbers |
| `--blue` | `#2a5a9e` | Code keywords |

### Dark/Light Mode Mechanic

The toggle switches between dark (default) and light mode. **In light mode, hidden writing appears in the background** — fake API keys, connection strings, and passwords scattered across the page as faint watermarks. This is invisible in dark mode and revealed in light mode.

**This is a visual/mechanical metaphor for ClassiFinder's product:** it reveals secrets hidden in text.

Implementation:
- Fixed-position div with `pointer-events: none` containing absolutely-positioned `<span>` elements
- Each span contains a realistic-looking secret (AWS key, Postgres connection string, Stripe key, etc.)
- Positioned at various rotations and locations across the page
- Opacity controlled by CSS custom property: `0` in dark mode, fades in with `transition: opacity 0.8s` in light mode
- Individual secrets have low opacity (~0.18) so they read as watermarks, not foreground content
- A subtle hint appears in light mode at bottom-left: "Look closely — secrets are hiding in the background"

### Mascot

The dog with magnifying glass (`assets/classifinder_dog4.jpg`) appears as a subtle background element:
- Fixed position, bottom-right corner
- Very low opacity (~6% dark, ~8% light)
- Inverted/filtered to match current theme
- `pointer-events: none` — purely decorative
- Think Firefox's fox: iconic but not in-your-face

### Decorative Elements

Noir-themed section dividers between major sections:
- Thin horizontal rule + centered bullet ornament (`• • •`) + thin horizontal rule
- Evokes chapter breaks in a novel

---

## Landing Page Sections

Each section has a monospace uppercase label ("The Evidence", "The Method") that frames the page as a detective's case file.

### 1. Hero

**Section label:** *(none — hero stands alone)*

**Content:**
- Badge: "Now in Early Access"
- Headline: "The case of the *leaked secret*" (italic "leaked secret" in green)
- Subheadline: "A stateless API that hunts down credentials hiding in your text — before they reach your LLM, your logs, or your users. One call. Nothing stored. Case closed."
- Two CTAs: "Try the Demo" (primary, anchors to #try-it) + "View Docs" (secondary, external link)
- Four stats: `50` secret types detected | `<5ms` engine time | `0 bytes` stored | `open source` engine on GitHub

### 2. Try It (Interactive Demo)

**Section label:** "The Evidence"

**Headline:** "Paste text. Watch secrets vanish."

**Subtext:** "Your text is scanned in real time. Nothing is stored or logged."

**Implementation:**
- Two-panel layout: Input (left) and Redacted Output (right)
- Input panel: editable textarea pre-filled with example secrets (Postgres connection string, Stripe key, AWS key)
- Output panel: shows redacted text with `[TYPE_REDACTED]` replacements, highlighted in green
- Below the panels: finding count, response time, endpoint label
- Calls the real ClassiFinder API (`POST /v1/redact`) with a rate-limited demo key
- Footer line: "POST /v1/redact · 50 patterns · more added every week"

**Interaction details:**
- A "Scan" button triggers the API call (not on every keystroke)
- Loading state: output panel shows a brief "Scanning..." indicator
- Error state: if API is unreachable, show "API unavailable — try again" inline in the output panel
- Initial state: pre-filled example text in input, output panel shows the pre-computed result (no API call needed on page load)

**Demo key considerations:**
- A dedicated demo API key hardcoded in the frontend (rate-limited server-side)
- Alternatively, a `/v1/demo` endpoint that requires no auth but is heavily rate-limited
- Decision deferred to implementation — either approach works

### 3. How It Works

**Section label:** "The Method"

**Headline:** "Three lines. Zero config."

**Content:**
- Three side-by-side code cards: Install (`pip install classifinder`), Scan (`client.scan(text)`), Ship (`prompt | Guard() | llm`)
- Full LangChain example code block below:
  ```python
  from classifinder.integrations.langchain import ClassiFinderGuard

  chain = prompt | ClassiFinderGuard() | llm | parser
  # Every prompt scanned and redacted before it hits the model
  # If ClassiFinder is unreachable, text passes through — your pipeline never breaks
  ```
- Code header label: "Available now" (LangChain integration is live)

### 4. Why ClassiFinder

**Section label:** "The Suspects"

**Headline:** "Every scanner was built for Git. This one's built for AI."

**Subtext:** "Secrets leak when users paste .env files into ChatGPT, when RAG pipelines surface credentials, and when agents hardcode keys into generated code."

**Content:** Comparison table (replaces the current card grid):

| | ClassiFinder | GitGuardian | Nightfall |
|---|---|---|---|
| Returns full secret? | Never | Yes | Varies |
| Free redaction? | Yes | No | Paid only |
| Confidence scores | 0.94 | Boolean | VERY_LIKELY |
| Pricing model | Per request | Per seat | Per seat |
| Data stored | 0 bytes | Stored | Stored |
| Built for AI pipelines? | Native | No | Partial |

ClassiFinder column highlighted in green.

### 5. Trust

**Section label:** "The Proof"

**Headline:** "Don't trust us. Read the code."

**Content:** 2x2 grid of trust cards:

1. **Open-source engine** — "The code that processes your text is MIT-licensed on GitHub. No database calls. No file writes. No logging of secret values. Read it yourself." (Links to GitHub repo)
2. **Honest limitations** — "50 known formats via regex. Won't catch custom tokens or passwords in natural language. One layer of defense — not the only one you need."
3. **Compliance-ready** — "Supports your SOC 2, PCI-DSS 4.0, and OWASP LLM Top 10 programs. Structured JSON findings provide auditable evidence." (Note: uses "Supports your" — not "Satisfies" or "Certified")
4. **Graceful failure** — "If ClassiFinder is unreachable, the LangChain guard passes text through unmodified. Your pipeline never breaks because of us."

### 6. Pricing

**Section label:** "The Fee"

**Headline:** "Free to start. Pay when you scale."

**Content:** Three-column grid:

- **Free** (active, green border): $0, no credit card required. Features: /scan and /redact, 50 secret types, 60 req/min, 256 KB payload, community support.
- **Starter** (dimmed): "Coming Soon" — higher limits & priority support.
- **Pro** (dimmed): "Coming Soon" — built for production workloads.

### 7. Get Key (Conversion Form)

**Section label:** *(none — centered CTA section)*

**Headline:** "Get your API key"

**Subtext:** "Start scanning in under a minute. Free forever for small projects."

**Form fields:**
- Email input (required)
- Checkbox: "Email me about new features and updates" (unchecked by default — opt-in)
- Submit button: "Create API Key"

**Behavior:**
- Form POSTs to `https://api.classifinder.tech/v1/keys/create`
- On success: display the API key with a copy button and warning "Save this — you won't see it again"
- On error: display error message inline
- **Dependency:** This endpoint must be deployed before the site launches. If not yet live, the form falls back to the existing Formspree submission (`https://formspree.io/f/mkoqlpkn`) with a "We'll email your key shortly" message.

### 8. Footer

**Content:**
- "ClassiFinder · Secret scanning for the AI era"
- Links: API Docs | GitHub | Patterns | Privacy | Terms
- Disclaimer text (from `docs/disclaimer.md`): brief liability/accuracy statement

---

## Patterns Page (`/patterns`)

Dedicated page listing all 50 detection patterns grouped by category.

**Source of truth:** `../classifinder/docs/pattern-library.md`

**Layout:**
- Same nav and footer as landing page
- Grouped by category (Cloud Provider Keys, Payment Keys, Database Connections, etc.)
- Each pattern shows: name, description, example (masked)
- Simple, scannable — like a reference document

---

## Astro Project Structure

```
classifinder-site/
├── astro.config.mjs
├── package.json
├── tsconfig.json
├── build.sh              # Updated: runs astro build (output → dist/)
├── wrangler.jsonc         # Existing: points assets at dist/
├── .github/
│   └── workflows/
│       └── deploy.yml     # Existing: npm run build → wrangler deploy
├── public/
│   └── assets/
│       └── classifinder_dog4.jpg
├── src/
│   ├── layouts/
│   │   └── BaseLayout.astro    # HTML shell, fonts, theme toggle, hidden secrets layer, dog bg
│   ├── components/
│   │   ├── Nav.astro
│   │   ├── Hero.astro
│   │   ├── Demo.astro           # Interactive demo (has client-side JS)
│   │   ├── HowItWorks.astro
│   │   ├── WhyClassiFinder.astro
│   │   ├── Trust.astro
│   │   ├── Pricing.astro
│   │   ├── GetKey.astro          # Key creation form (has client-side JS)
│   │   ├── Footer.astro
│   │   ├── SectionDivider.astro  # Noir ornament divider
│   │   ├── ThemeToggle.astro     # Dark/Light? toggle
│   │   └── HiddenSecrets.astro   # Background secrets layer
│   ├── pages/
│   │   ├── index.astro           # Landing page — composes all section components
│   │   ├── patterns.astro        # Pattern library page
│   │   ├── privacy-policy.astro  # Wraps existing content in layout
│   │   └── terms-of-service.astro
│   └── styles/
│       └── global.css            # CSS custom properties, theme vars, base styles
└── dist/                          # Build output (gitignored)
```

### Key Technical Decisions

- **Astro with zero JS by default.** Only `Demo.astro` and `GetKey.astro` need client-side JavaScript (for API calls). These use `<script>` tags or Astro's `client:load` directive.
- **No framework (React, Vue, etc.)** — plain Astro components with vanilla JS where needed. Keeps the bundle tiny.
- **CSS custom properties** for theming — the dark/light toggle sets `data-theme` on `<html>` and CSS handles the rest via variable swaps.
- **`build.sh` updated** to run `npm run build` (which runs `astro build`), outputting to `dist/`. The GitHub Actions workflow and wrangler config remain unchanged.
- **Static output** — Astro builds to static HTML. No SSR needed.

---

## Deploy Pipeline Changes

The existing pipeline (`build.sh` → GitHub Actions → `wrangler deploy`) stays intact. Only `build.sh` changes:

**Before:**
```bash
cp index.html dist/
cp privacy-policy.html dist/
```

**After:**
```bash
npm run build  # astro build → outputs to dist/
```

The `wrangler.jsonc` already points at `./dist` so no changes there.

---

## Content Fixes Incorporated

All launch-blocking items from `todo.md` are addressed in this design:

| Todo Item | Where It's Addressed |
|-----------|---------------------|
| Update Free tier limits | Pricing section: 60 req/min, 256 KB, 50 types |
| Block Starter/Pro tiers | Pricing section: "Coming Soon" with dimmed styling |
| Soften compliance language | Trust section: "Supports your SOC 2..." not "Satisfies" |
| Add limitations statement | Trust section: "Honest limitations" card |
| Add open-source trust callout | Trust section: "Open-source engine" card + hero stat |
| Add graceful failure note | Trust section: "Graceful failure" card + code comment |
| Update pattern count to 50 | Hero stats, pricing features, demo footer |
| Update SDK to "pip install classifinder" | How It Works section |
| Update LangChain status to "available" | How It Works section: "Available now" label |
| Link to open-source engine | Trust section, footer |
| Form → /v1/keys/create | Get Key section |
| Show API key after creation | Get Key section behavior |
| Opt-in email checkbox | Get Key section: unchecked by default |
| Footer links to privacy/terms | Footer |
| Add "more patterns added every week" | Demo section footer line |
| Benchmark latency clarification | Hero stat: "<5ms engine time" (not total latency) |
| Add 50-pattern detection list | Separate `/patterns` page (linked from nav and footer) |
| Add disclaimer text to footer | Footer: inline disclaimer from `docs/disclaimer.md` |
| Add privacy-policy.html | `/privacy-policy` route in Astro |
| Add terms-of-service.html | `/terms-of-service` route (placeholder if Termly content not yet ready) |

---

## Responsive Design

Breakpoint at `700px` (consistent with the current site):

| Component | Desktop | Mobile (≤700px) |
|-----------|---------|-----------------|
| Demo panels | Side-by-side grid | Stacked vertically |
| How It Works cards | 3-column row | Stacked vertically |
| Comparison table | Full table | Horizontally scrollable |
| Trust grid | 2x2 grid | Single column |
| Pricing grid | 3-column row | Single column |
| Hero stats | Horizontal row | Stacked vertically |
| Nav links | Inline | Hamburger menu or collapsible |

---

## Accessibility

- Hidden secrets layer: `aria-hidden="true"` on the container div — screen readers must not read the watermark secrets
- Dog mascot image: empty `alt=""` (decorative)
- Theme toggle: `aria-label="Toggle theme"`, announce current state to screen readers
- All interactive elements (demo button, form inputs, nav links) must be keyboard-navigable
- Color contrast: all text/background combinations must meet WCAG 2.1 AA (4.5:1 for body text, 3:1 for large text)
- `BaseLayout.astro` must include `<html lang="en">`, proper `<title>`, and `<meta name="description">`

---

## Open Questions

1. **Demo API key strategy:** Hardcoded demo key in frontend vs. unauthenticated `/v1/demo` endpoint. Either works; the API team should decide based on abuse risk.
2. **Patterns page data source:** Should the pattern list be hardcoded in the Astro page, or fetched from the API's `GET /v1/types` endpoint at build time?
3. **Open Graph / social sharing meta tags:** The Gemini analysis recommended these. Should be added to `BaseLayout.astro` — needs a preview image designed.
4. **Favicon:** Gemini flagged the missing favicon. Should we use the dog, the magnifying glass, or a custom icon?
