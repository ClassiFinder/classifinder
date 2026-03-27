# Termly Policy Update Triggers

Things that will require updating your Termly privacy policy, terms of service, or disclaimer when they happen.

---

## When You Add Payments
- Add Stripe to "Invoicing & Billing" third-party services
- Change "Do you accept payments online?" to Yes
- Add billing address and debit/credit card numbers to collected personal information
- Update data processing agreements section if Stripe DPA is signed

## When You Add the Mailing List / Marketing Emails
Priority: first week post-launch, before user count makes it painful to retroactively collect opt-ins.

**What to build:**
- Add `subscribe` boolean field to `KeyCreateRequest` (opt-in checkbox on landing page)
- Add `marketing_opt_in` column to `api_keys` table in Turso
- Integrate an email service (Resend, Buttondown, or Mailchimp)
- Only email users who explicitly opted in — never auto-subscribe

**Termly updates required:**
- Add email service (Resend, SendGrid, etc.) to third-party services under "Communicate & Chat with Users" or "Advertising, Direct Marketing"
- Add "To send administrative information to users" to how you use personal information
- If adding marketing emails: add consent/opt-in language
- Update collected personal information if storing any new fields (e.g., name)

## When You Add Email Verification for Key Provisioning
- Update data flow description (email verification step)
- Add email service provider to third-party services

## When You Add Analytics
- Add analytics provider (e.g., Plausible, PostHog) to "Web & Mobile Analytics"
- Update derivative data section if collecting device data or location data
- May require cookie consent banner if using cookie-based analytics

## When You Add User Accounts / Dashboard
- Change "Can users create an account?" to Yes
- Add usernames/passwords to collected personal information if applicable
- Update "User Account Registration & Authentication" third-party services if using OAuth

## When You Add SOC 2 / Enterprise Features
- Sign DPAs with Turso, Fly.io, Cloudflare — update "Do you have data processing agreements?" to Yes
- Add any new infrastructure providers to third-party services list

## When You Add Self-Hosted / On-Premise Option
- Separate privacy policy section for self-hosted (no data leaves customer infra)

## When You Expand to EU Customers Specifically
- Review GDPR compliance sections in Termly
- Add data transfer mechanisms (Standard Contractual Clauses) if storing EU user emails in US infrastructure
- Consider appointing an EU representative if required by volume
