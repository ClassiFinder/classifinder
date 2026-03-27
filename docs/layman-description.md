# ClassiFinder — What Is This Thing?

## The Problem

Developers accidentally paste passwords, API keys, and other secrets into places they shouldn't — chat messages, code files, log outputs, AI prompts. Once a secret leaks, attackers can use it to access your cloud accounts, databases, or payment systems. The damage can be enormous, and it happens constantly.

## What ClassiFinder Does

ClassiFinder is a web service (an API) that you send text to, and it tells you if there are any secrets hiding in it. Think of it like a spell-checker, but instead of catching typos, it catches leaked passwords and API keys.

You send it text. It sends back a report telling you:
- **What it found** — "There's an AWS key on line 3 and a database password on line 7"
- **How dangerous it is** — critical, high, medium, or low severity
- **How confident it is** — "98% sure this is real" vs. "60% sure, might be a false alarm"
- **What to do about it** — "Rotate this key immediately in the AWS console"

It can also **redact** (blank out) the secrets and give you back a clean version of the text. This is especially useful if you're about to send user input to an AI model — you can run it through ClassiFinder first to strip out any secrets before the AI ever sees them.

## How It Works (Simply)

1. **You send text** to ClassiFinder over HTTP (the same way your browser talks to websites)
2. **It pattern-matches** against 46 known secret formats — things like AWS keys (which always start with `AKIA`), Stripe keys (which start with `sk_live_`), GitHub tokens, database connection strings, private keys, and more
3. **It scores each match** — is this likely a real secret, or a false alarm? It looks at surrounding context (is the word "password" nearby?), randomness (real keys look random, fake ones don't), and whether it's a known example/test value
4. **It sends back JSON** — structured data your code can easily parse and act on

The whole process takes about 5 milliseconds. There's no database behind it — nothing is stored. Your text goes in, the report comes out, and the text is gone.

## The Endpoints (URLs You Can Call)

Think of these like different "commands" you can give ClassiFinder:

- **Scan** (`POST /v1/scan`) — "Here's some text, tell me what secrets are in it"
- **Redact** (`POST /v1/redact`) — "Here's some text, give me back a clean version with secrets blanked out"
- **Types** (`GET /v1/types`) — "What kinds of secrets can you detect?"
- **Health** (`GET /v1/health`) — "Are you running okay?"
- **Feedback** (`POST /v1/feedback`) — "You flagged this thing, but it's not actually a secret" (helps improve detection)

## Authentication

Every request (except health checks) needs an API key passed in a header. This is like a password that identifies who's calling the API. Keys look like `ss_live_abc123...` for production or `ss_test_abc123...` for testing.

## What Does "Stateless" Mean?

ClassiFinder doesn't remember anything between requests. There's no database, no user accounts, no history of what you've scanned. Each request is completely independent. This is a deliberate design choice — since users are sending potentially sensitive text, the safest thing to do is not store any of it.

## Security: What ClassiFinder Never Does

- **Never returns the full secret** — If it finds your AWS key `AKIAIOSFODNN7EXAMPLE`, it only shows `AKIA****MPLE` in the response. You already have the full text; we don't need to echo it back.
- **Never logs your text** — The server logs record things like "a request came in at 2:30pm, it was 4KB, we found 3 secrets, it took 5ms." It never records *what* the text said.
- **Never stores anything** — No database, no files, no caches. Text goes in, report comes out, text is forgotten.

## Who Would Use This?

- **AI/LLM applications** — Run user input through ClassiFinder before sending it to ChatGPT/Claude/etc., so secrets never reach the model
- **CI/CD pipelines** — Automatically scan code changes for leaked secrets before they get merged
- **Chat platforms** — Check messages for accidentally pasted credentials
- **Security teams** — Scan logs, configs, or documents for credential exposure

## Running It Locally

If you want to try it out:

```bash
# Install the dependencies
pip install -r requirements.txt

# Start the server (replace "yourkey" with whatever you want your API key to be)
CLASSIFINDER_API_KEYS=ss_test_yourkey123456789012345678901234567890 uvicorn app.main:app --port 8000
```

Then open `http://localhost:8000/docs` in your browser — you'll get an interactive page where you can try out all the endpoints without writing any code.

## The Tech (For the Curious)

- **Python** — The programming language everything is written in
- **FastAPI** — A popular Python framework for building web APIs (handles the HTTP stuff)
- **Pydantic** — Validates that incoming requests have the right shape and types
- **Uvicorn** — The web server that actually listens for connections

That's it. No database, no message queue, no cloud services, no complex infrastructure. Just a Python app that pattern-matches text and returns JSON.
