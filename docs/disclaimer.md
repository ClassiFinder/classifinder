# ClassiFinder — Disclaimer and Legal Text

Draft text for use on the landing page, API docs, and SDK README. Have a lawyer review before publishing.

---

## API Disclaimer (short form)

Use on: landing page footer, Swagger UI, SDK README, API docs.

> ClassiFinder is a detection aid, not a guarantee. While we work to maintain accurate and comprehensive secret detection, no scanner catches 100% of secrets in 100% of formats. ClassiFinder should be used as one layer of a defense-in-depth security strategy, not as a sole safeguard. By using this service, you acknowledge that ClassiFinder is provided "as-is" without warranty of any kind. See our Terms of Service for full details.

---

## Limitation of Liability (for Terms of Service)

> TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, CLASSIFINDER AND ITS AFFILIATES, OFFICERS, EMPLOYEES, AGENTS, AND LICENSORS SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED DIRECTLY OR INDIRECTLY, OR ANY LOSS OF DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES, RESULTING FROM (A) YOUR USE OF OR INABILITY TO USE THE SERVICE; (B) ANY SECRETS, CREDENTIALS, OR SENSITIVE DATA THAT THE SERVICE FAILS TO DETECT; (C) ANY UNAUTHORIZED ACCESS TO OR ALTERATION OF YOUR TRANSMISSIONS OR DATA; OR (D) ANY OTHER MATTER RELATING TO THE SERVICE.
>
> IN NO EVENT SHALL CLASSIFINDER'S AGGREGATE LIABILITY EXCEED THE GREATER OF THE AMOUNT YOU PAID CLASSIFINDER IN THE TWELVE (12) MONTHS PRIOR TO THE EVENT GIVING RISE TO LIABILITY, OR ONE HUNDRED DOLLARS ($100).

---

## Warranty Disclaimer (for Terms of Service)

> THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. CLASSIFINDER DOES NOT WARRANT THAT (A) THE SERVICE WILL BE UNINTERRUPTED, TIMELY, SECURE, OR ERROR-FREE; (B) THE SERVICE WILL DETECT ALL SECRETS, CREDENTIALS, OR SENSITIVE DATA IN ALL FORMATS; OR (C) THE RESULTS OBTAINED FROM THE SERVICE WILL BE ACCURATE OR RELIABLE.

---

## Data Handling Statement (for Privacy Policy)

> ClassiFinder processes text submitted via the API in server memory only. Text is not written to disk, stored in a database, cached, or logged. Request bodies and response bodies are never persisted. Only operational metadata is logged: request ID, API key hash (first 8 characters of SHA-256, never the key itself), timestamp, HTTP method, endpoint path, request size in bytes, finding count (a number, never the findings themselves), response time in milliseconds, and HTTP status code.
>
> For key provisioning, we store: a SHA-256 hash of your API key (not the key itself), your email address, your pricing tier, and the timestamp of key creation. This data is stored in a hosted SQLite database (Turso) and is used solely for authentication and billing purposes.
>
> For feedback reports (false positive / false negative submissions via POST /v1/feedback), we store: a unique feedback ID, the request ID and finding ID from the original scan, the feedback classification ("false_positive" or "false_negative"), a boolean indicating whether a comment was provided (the comment text itself is never stored), the expected pattern type (for false negatives), and a timestamp. Feedback records are anonymous — no user identity or API key hash is stored alongside them. This data is stored in Turso and is used solely to improve detection accuracy. No scanned text, secret values, or user-provided comment text is ever persisted.

---

## No-Storage Architecture Statement (for landing page / docs)

> ClassiFinder is stateless by design. Your text is processed in memory and discarded after the response is sent. We never store request bodies, secrets, findings, or scan history. The data we retain is limited to: your email address and a hash of your API key (for authentication), and anonymous feedback metadata if you submit false positive or false negative reports (IDs, classification, and timestamps — no user identity, scanned text, secret values, or comment text). We built it this way because users send us their secrets by definition. The safest thing to do with sensitive data is not keep it.

---

## Notes

- These are drafts. Have a lawyer review them before publishing, especially the limitation of liability and warranty disclaimer sections.
- The limitation of liability clause caps exposure at the amount paid or $100, whichever is greater. This is standard SaaS practice.
- The "as-is" warranty disclaimer is required to disclaim implied warranties under US law (UCC Article 2).
- The data handling statement can be expanded into a full privacy policy using Termly or iubenda as a starting point.
