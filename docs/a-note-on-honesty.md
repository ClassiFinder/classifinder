That's a sharp question, and the honest answer is that you can't _prove_ it in a cryptographic sense. There's no technical mechanism that lets an external user verify that your server didn't write their request body to a disk somewhere. This is a fundamental trust problem — it's the same reason people can't truly verify that OpenAI or Anthropic don't store their prompts beyond what the privacy policy claims.

But there are several things you can do that range from "builds confidence" to "as close to proof as you can get."

**Things that are actually verifiable:**

Open-source the scanner engine. If the core scanning logic is public on GitHub, anyone can read it and confirm there's no database call, no file write, no network call to a logging service. The engine is already a pure function with no I/O — that's auditable. You keep the hosted infrastructure and pattern library private (that's your business), but the code that touches user data is transparent. This is the single strongest trust signal you can offer.

Publish your Dockerfile. If users can see that the container runs a stateless FastAPI app with no database driver, no persistent volume mount, and no logging SDK that captures request bodies, they can reason about what the service _can_ do. A container with nothing but Python, FastAPI, and uvicorn has a small surface area.

**Things that build strong confidence:**

SOC 2 Type II certification. This is the gold standard for "a third party audited our data handling practices." SOC 2 specifically examines how you handle, process, and store customer data. Getting certified means an auditor verified your no-storage claims. This is expensive and premature for MVP, but it's the long-term answer for enterprise buyers.

A detailed privacy architecture page on your docs site. Not a legal privacy policy — a _technical_ description of how requests flow through the system. Explain that request bodies exist only in process memory, that they're garbage collected after the response is sent, that your logging middleware captures only metadata (and show the exact schema of what you log), that you use no persistent storage, and that there's no way to replay a request because nothing was recorded. Include a diagram. Developers trust architecture docs more than legal language.

Penetration test reports. Hire a security firm to audit the deployed service and publish the results. If they confirm there's no data at rest, no request body in any log, and no way to reconstruct past requests, that's third-party validation.

**Things that help but aren't proof:**

Response headers that signal statelessness. Include a header like `X-Data-Retention: none` on every response. It's not proof, but it's a public commitment baked into every API call that would be embarrassing to violate.

A canary or warrant canary approach. Publish a standing statement: "ClassiFinder has never been compelled to store request data or provide request bodies to any third party." Update it regularly. If it disappears, users know something changed.

Short request timeouts and no retry queue. If your infrastructure has no message queue, no retry mechanism, and no async processing — requests either complete in memory and return, or they fail — there's nowhere for data to linger. Document this architecture.

**The uncomfortable truth:**

Ultimately, using any hosted API requires trusting the operator. The best you can do is minimize what users _have_ to trust by making as much as possible auditable (open source engine, public Dockerfile, published log schemas), and then back up the rest with third-party verification (SOC 2, pen tests). The combination of "I can read the code that touches my data" plus "an auditor confirmed the infrastructure matches what they claim" gets you as close to proof as the industry allows.

The open-source engine is the move I'd prioritize. It costs you nothing — the patterns are your IP, but the scan/redact logic is commodity code. And it directly addresses the trust question in a way that no privacy policy ever will.
