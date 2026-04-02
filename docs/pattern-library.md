# ClassiFinder — Pattern Library (71 Patterns)

All 71 secret detection patterns supported by ClassiFinder, organized by category. Each entry includes the pattern ID, what it detects, an example of what triggers it, and the core regex used for matching.

---

## Cloud Providers (15 patterns)

### 1. `aws_access_key` — AWS Access Key ID

AWS IAM access key, 20 characters starting with AKIA (permanent) or ASIA (temporary STS). Leaked AWS keys are the #1 cause of cloud account takeover.

**Example:** `AKIAIOSFODNN7EXAMPLE`

**Regex:** `(?:AKIA|ASIA)[0-9A-Z]{16,20}`

---

### 2. `aws_secret_key` — AWS Secret Access Key

AWS IAM secret access key, 40-character base64 string. Usually paired with an access key ID. Detected when preceded by context like `AWS_SECRET_ACCESS_KEY=`.

**Example:** `AWS_SECRET_ACCESS_KEY=aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5A`

**Regex:** `(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey|secret_access_key)[\s]*[=:"'\s]+[A-Za-z0-9/+=]{40}`

---

### 3. `gcp_api_key` — GCP API Key

Google Cloud Platform API key, 39 characters starting with AIza. Also covers Google AI (Gemini) API keys which use the same format.

**Example:** `AIzaSyAFAKEKEYFORTESTING123456789012345`

**Regex:** `AIza[0-9A-Za-z\-_]{35}`

---

### 4. `gcp_service_account_key` — GCP Service Account Key (JSON fragment)

Fragment of a Google Cloud service account JSON key file, identified by the `private_key` field containing a PEM-encoded RSA key.

**Example:** `"private_key": "-----BEGIN RSA PRIVATE KEY-----MIIEfakeKeyDataAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-----END RSA PRIVATE KEY-----\n"`

**Regex:** `"private_key"\s*:\s*"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----[^"]{50,2048}-----END\s(?:RSA\s)?PRIVATE\sKEY-----\\n"`

---

### 5. `azure_storage_key` — Azure Storage Account Key

Azure Storage account access key, 88-character base64 string ending with `==`. Detected when preceded by `AccountKey` or similar context.

**Example:** `AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUV==`

**Regex:** `(?:AccountKey|account_key|AZURE_STORAGE_KEY|azure_storage_key)[\s]*[=:"'\s]+[A-Za-z0-9+/]{86}==`

---

### 6. `azure_ad_client_secret` — Azure AD Client Secret

Azure Active Directory application client secret. Typically 34-44 characters, detected with context keywords like `AZURE_CLIENT_SECRET`.

**Example:** `AZURE_CLIENT_SECRET=a1b2c3d4~e5f6.g7h8_i9j0k1l2m3n4o5p6q7`

**Regex:** `(?:AZURE_CLIENT_SECRET|client_secret|clientSecret)[\s]*[=:"'\s]+[A-Za-z0-9~_.]{34,44}`

---

### 7. `digitalocean_token` — DigitalOcean Personal Access Token

DigitalOcean API token with `dop_v1_` prefix followed by 64 hex characters.

**Example:** `dop_v1_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2`

**Regex:** `dop_v1_[a-f0-9]{64}`

---

### 8. `heroku_api_key` — Heroku API Key

Heroku API key in UUID format, detected when preceded by `HEROKU_API_KEY` or similar context.

**Example:** `HEROKU_API_KEY=12345678-abcd-1234-abcd-123456789abc`

**Regex:** `(?:HEROKU_API_KEY|heroku_api_key|heroku.*api.*key)[\s]*[=:"'\s]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

---

### 9. `cloudflare_api_token` — Cloudflare API Token

Cloudflare API token, 40-character alphanumeric string. Detected with context like `CLOUDFLARE_API_TOKEN`.

**Example:** `CLOUDFLARE_API_TOKEN=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0`

**Regex:** `(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|cloudflare.*token)[\s]*[=:"'\s]+[A-Za-z0-9_\-]{40}`

---

### 10. `doppler_token` — Doppler Service Token

Doppler service token with `dp.pt.` prefix followed by 40-44 alphanumeric characters. Grants access to Doppler secrets management.

**Example:** `dp.pt.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr`

**Regex:** `dp\.pt\.[A-Za-z0-9]{40,44}`

---

### 11. `terraform_cloud_token` — Terraform Cloud API Token

Terraform Cloud API token with `.atlasv1.` separator. Grants access to Terraform Cloud workspaces and state.

**Example:** `ABCDEFGHIJKLmn.atlasv1.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDE`

**Regex:** `[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}`

---

### 12. `vault_token` — HashiCorp Vault Token

HashiCorp Vault token with `hvs.` prefix. Grants access to secrets stored in Vault.

**Example:** `hvs.ABCDEFGHIJKLMNOPQRSTUVwx`

**Regex:** `hvs\.[A-Za-z0-9]{24,}`

---

### 13. `pulumi_access_token` — Pulumi Access Token

Pulumi access token with `pul-` prefix followed by 40 hex characters. Grants access to Pulumi Cloud infrastructure state.

**Example:** `pul-abcdef0123456789abcdef0123456789abcdef01`

**Regex:** `pul-[a-f0-9]{40}`

---

### 14. `fly_api_token` — Fly.io API Token

Fly.io API token with `fo1_` prefix followed by 39 alphanumeric characters. Grants access to Fly.io app management.

**Example:** `fo1_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm`

**Regex:** `fo1_[A-Za-z0-9]{39}`

---

### 15. `alibaba_access_key` — Alibaba Cloud Access Key ID

Alibaba Cloud access key ID with `LTAI` prefix followed by 17-21 alphanumeric characters.

**Example:** `LTAIabcdefghijklmnopq`

**Regex:** `LTAI[A-Za-z0-9]{17,21}`

---

## Payment & Financial (11 patterns)

### 16. `stripe_live_secret_key` — Stripe Live Secret Key

Stripe live-mode secret API key. Grants full access to a live Stripe account including charges, refunds, and customer data.

**Example:** `sk_live_51H3aKLkdsjfhDKJSH38djfhksd`

**Regex:** `sk_live_[a-zA-Z0-9]{24,99}`

---

### 17. `stripe_test_secret_key` — Stripe Test Secret Key

Stripe test-mode secret API key. Cannot process real payments but reveals account structure.

**Example:** `sk_test_4eC39HqLyjWDarjtT1zdp7dc`

**Regex:** `sk_test_[a-zA-Z0-9]{24,99}`

---

### 18. `stripe_live_publishable_key` — Stripe Live Publishable Key

Stripe live-mode publishable key. Semi-public by design but shouldn't appear in server-side code or logs.

**Example:** `pk_live_51H3aKLkdsjfhDKJSH38djfhksd`

**Regex:** `pk_live_[a-zA-Z0-9]{24,99}`

---

### 19. `stripe_webhook_secret` — Stripe Webhook Signing Secret

Stripe webhook endpoint signing secret, used to verify incoming webhook payloads.

**Example:** `whsec_1234abcd5678efgh9012ijkl`

**Regex:** `whsec_[a-zA-Z0-9]{24,99}`

---

### 20. `stripe_restricted_key` — Stripe Restricted API Key

Stripe restricted API key with limited permissions. Still sensitive — may include read access to customer or payment data.

**Example:** `rk_live_51H3aKLkdsjfhDKJSH38djfhksd`

**Regex:** `rk_live_[a-zA-Z0-9]{24,99}`

---

### 21. `paypal_client_secret` — PayPal Client Secret

PayPal REST API client secret, used with client ID for OAuth authentication. Detected with context keywords.

**Example:** `PAYPAL_CLIENT_SECRET=EBWKjlELKMYqRNQ6sYvFo64FtaRLRR5BdHEESmha49TM3xY7z9A`

**Regex:** `(?:PAYPAL_CLIENT_SECRET|paypal.*client.*secret|paypal.*secret)[\s]*[=:"'\s]+E[A-Za-z0-9\-]{50,80}`

---

### 22. `square_access_token` — Square Access Token

Square API access token with `EAA` prefix.

**Example:** `EAAl4ZByvnpkBAKLZCr7wQd2oRbZBJZCWzeqFhd8MxZBXD5pEM`

**Regex:** `EAA[a-zA-Z0-9\-_]{40,100}`

---

### 23. `credit_card_number` — Credit Card Number

Credit card number (Visa, Mastercard, Amex, Discover) with Luhn checksum validation. Supports numbers with or without dashes/spaces.

**Example:** `4532015112830366`

**Regex:** `(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[\s\-]?[0-9]{4,6}[\s\-]?[0-9]{4,5}(?:[\s\-]?[0-9]{4})?`

*Note: Matches are also validated with the Luhn algorithm. Numbers that fail the checksum are dropped to very low confidence.*

---

### 24. `shopify_access_token` — Shopify Admin API Access Token

Shopify Admin API access token with `shpat_` prefix followed by 32 hex characters. Grants access to a Shopify store's admin API.

**Example:** `shpat_abcdef0123456789abcdef0123456789`

**Regex:** `shpat_[a-fA-F0-9]{32}`

---

### 25. `shopify_custom_token` — Shopify Custom App Access Token

Shopify custom app access token with `shpca_` prefix followed by 32 hex characters.

**Example:** `shpca_abcdef0123456789abcdef0123456789`

**Regex:** `shpca_[a-fA-F0-9]{32}`

---

### 26. `shopify_private_token` — Shopify Private App Access Token

Shopify private app access token with `shppa_` prefix followed by 32 hex characters.

**Example:** `shppa_abcdef0123456789abcdef0123456789`

**Regex:** `shppa_[a-fA-F0-9]{32}`

---

## Version Control & CI/CD (12 patterns)

### 27. `github_pat_classic` — GitHub Personal Access Token (Classic)

GitHub classic personal access token with `ghp_` prefix.

**Example:** `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh`

**Regex:** `ghp_[A-Za-z0-9]{30,40}`

---

### 28. `github_pat_fine_grained` — GitHub Fine-Grained Personal Access Token

GitHub fine-grained PAT with `github_pat_` prefix and repository-level permissions.

**Example:** `github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

**Regex:** `github_pat_[A-Za-z0-9_]{82}`

---

### 29. `github_oauth_secret` — GitHub OAuth App Client Secret

GitHub OAuth application client secret with `gho_` prefix.

**Example:** `gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`

**Regex:** `gho_[A-Za-z0-9]{36}`

---

### 30. `github_app_installation_token` — GitHub App Installation Access Token

GitHub App installation token with `ghs_` prefix. Short-lived (1 hour) but grants repository access.

**Example:** `ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`

**Regex:** `ghs_[A-Za-z0-9]{36}`

---

### 31. `github_user_to_server_token` — GitHub User-to-Server Token

GitHub user-to-server token with `ghu_` prefix, used by GitHub Apps acting on behalf of a user.

**Example:** `ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`

**Regex:** `ghu_[A-Za-z0-9]{36}`

---

### 32. `gitlab_pat` — GitLab Personal Access Token

GitLab personal access token with `glpat-` prefix.

**Example:** `glpat-ABCDEFGHIJKLMNOPQRST`

**Regex:** `glpat-[A-Za-z0-9\-_]{20,}`

---

### 33. `gitlab_pipeline_trigger` — GitLab Pipeline Trigger Token

GitLab CI pipeline trigger token with `glptt-` prefix. Can trigger arbitrary pipelines.

**Example:** `glptt-ABCDEFGHIJKLMNOPQRST`

**Regex:** `glptt-[A-Za-z0-9\-_]{20,}`

---

### 34. `bitbucket_app_password` — Bitbucket App Password

Bitbucket app password, detected with context keywords like `BITBUCKET_APP_PASSWORD`.

**Example:** `BITBUCKET_APP_PASSWORD=a1b2c3d4e5f6g7h8i9j0`

**Regex:** `(?:BITBUCKET_APP_PASSWORD|bitbucket.*password|bitbucket.*token)[\s]*[=:"'\s]+[A-Za-z0-9]{20,40}`

---

### 35. `circleci_token` — CircleCI API Token

CircleCI personal or project API token, 40-character hex string. Detected with context.

**Example:** `CIRCLECI_TOKEN=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`

**Regex:** `(?:CIRCLECI_TOKEN|CIRCLE_TOKEN|circleci.*token)[\s]*[=:"'\s]+[a-f0-9]{40}`

---

### 36. `npm_token` — npm Access Token

npm access token with `npm_` prefix followed by 36 alphanumeric characters. Grants publish access to npm packages.

**Example:** `npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`

**Regex:** `npm_[A-Za-z0-9]{36}`

---

### 37. `pypi_token` — PyPI API Token

PyPI API token with `pypi-AgEIcHlwaS5vcmc` prefix. Grants publish access to Python packages on PyPI.

**Example:** `pypi-AgEIcHlwaS5vcmcCJGI0ZjE3YjFkLTk1NDMtNGRiMS1hYjFhLThlOTIxMTk3N2YzNg`

**Regex:** `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`

---

### 38. `rubygems_token` — RubyGems API Key

RubyGems API key with `rubygems_` prefix followed by 48 alphanumeric characters. Grants publish access to Ruby gems.

**Example:** `rubygems_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv`

**Regex:** `rubygems_[A-Za-z0-9]{48}`

---

## Communications & SaaS (15 patterns)

### 39. `slack_bot_token` — Slack Bot Token

Slack bot user OAuth token with `xoxb-` prefix. Grants bot-level access to a workspace.

**Example:** `xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx`

**Regex:** `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,36}`

---

### 40. `slack_user_token` — Slack User Token

Slack user OAuth token with `xoxp-` prefix. More privileged than bot tokens — has the permissions of the authorizing user.

**Example:** `xoxp-1234567890-1234567890123-1234567890123-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

**Regex:** `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`

---

### 41. `slack_webhook_url` — Slack Incoming Webhook URL

Slack incoming webhook URL that allows posting messages to a specific channel without authentication.

**Example:** `https://hooks.slack.com/services/T01234567/B01234567AB/abcdefghijklmnopqrstuvwx`

**Regex:** `https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}`

---

### 42. `twilio_account_sid` — Twilio Account SID

Twilio Account SID, 34 characters starting with `AC`. Not secret alone but often found alongside auth tokens.

**Example:** `ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

**Regex:** `AC[a-f0-9]{32}`

---

### 43. `twilio_auth_token` — Twilio Auth Token

Twilio Auth Token, 32-character hex string. Used with Account SID for API authentication. Detected with context.

**Example:** `TWILIO_AUTH_TOKEN=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

**Regex:** `(?:TWILIO_AUTH_TOKEN|twilio.*auth.*token|auth_token)[\s]*[=:"'\s]+[a-f0-9]{32}`

---

### 44. `sendgrid_api_key` — SendGrid API Key

SendGrid API key with distinctive `SG.` prefix and two dot-separated segments.

**Example:** `SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs`

**Regex:** `SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`

---

### 45. `mailgun_api_key` — Mailgun API Key

Mailgun API key with `key-` prefix followed by a 32-character hex string.

**Example:** `key-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

**Regex:** `key-[a-f0-9]{32}`

---

### 46. `discord_bot_token` — Discord Bot Token

Discord bot token. Three base64 segments separated by dots. The first segment starts with M or N.

**Example:** `MTAwMDAwMDAwMDAwMDAwMDAw.G1234A.abcdefghijklmnopqrstuvwxyz1234567`

**Regex:** `[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`

---

### 47. `telegram_bot_token` — Telegram Bot Token

Telegram Bot API token. Numeric bot ID followed by a colon and a 35-character alphanumeric string.

**Example:** `123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi`

**Regex:** `[0-9]{8,10}:[A-Za-z0-9_\-]{35}`

---

### 48. `newrelic_admin_api_key` — New Relic Admin API Key

New Relic Admin API key with `NRAA-` prefix followed by 27 hex characters. Grants full administrative access to New Relic.

**Example:** `NRAA-abcdef0123456789abcdef01234`

**Regex:** `NRAA-[a-f0-9]{27}`

---

### 49. `newrelic_insights_key` — New Relic Insights Insert/Query Key

New Relic Insights key with `NRII-` or `NRIQ-` prefix followed by 32 alphanumeric characters. Used for inserting or querying event data.

**Example:** `NRII-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef`

**Regex:** `NRI[IQ]-[A-Za-z0-9\-_]{32}`

---

### 50. `newrelic_user_api_key` — New Relic User API Key

New Relic user API key with `NRAK-` prefix followed by 27 lowercase alphanumeric characters.

**Example:** `NRAK-abc0123456789def0123456789a`

**Regex:** `NRAK-[a-z0-9]{27}`

---

### 51. `grafana_api_key` — Grafana Service Account Token

Grafana service account token with `glsa_` prefix, 32 alphanumeric characters, underscore separator, and 8 hex characters.

**Example:** `glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_abcdef01`

**Regex:** `glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`

---

### 52. `linear_api_key` — Linear API Key

Linear API key with `lin_api_` prefix followed by 40 alphanumeric characters. Grants access to Linear project management.

**Example:** `lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn`

**Regex:** `lin_api_[A-Za-z0-9]{40}`

---

### 53. `notion_api_key` — Notion Integration Token

Notion integration token with `secret_` prefix followed by 43 alphanumeric characters. Grants access to Notion workspaces.

**Example:** `secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef`

**Regex:** `secret_[A-Za-z0-9]{43}`

---

## Database & Infrastructure (7 patterns)

### 54. `postgres_connection_string` — PostgreSQL Connection String

PostgreSQL connection URI with embedded username and password.

**Example:** `postgres://admin:s3cur3p4ss@db.internal:5432/production`

**Regex:** `postgres(?:ql)?://[^:@\s]{1,64}:[^@\s]{1,128}@[^/\s]{1,256}(?:/[^\s"']{0,128})?`

---

### 55. `mysql_connection_string` — MySQL Connection String

MySQL connection URI with embedded credentials. Supports `+pymysql` and `+mysqlconnector` drivers.

**Example:** `mysql+pymysql://root:password@localhost:3306/mydb`

**Regex:** `mysql(?:\+pymysql|\+mysqlconnector)?://[^:@\s]{1,64}:[^@\s]{1,128}@[^/\s]{1,256}(?:/[^\s"']{0,128})?`

---

### 56. `mongodb_connection_string` — MongoDB Connection String

MongoDB connection URI with embedded credentials. Matches both `mongodb://` and `mongodb+srv://` schemes.

**Example:** `mongodb+srv://user:MyP4ssword@cluster0.abc123.mongodb.net/mydb`

**Regex:** `mongodb(?:\+srv)?://[^:@\s]{1,64}:[^@\s]{1,128}@[^\s"']{1,512}`

---

### 57. `redis_connection_string` — Redis Connection String

Redis connection URI with embedded password.

**Example:** `redis://:s3cretP4ss@redis.internal:6379/0`

**Regex:** `redis(?:s)?://(?:[^:@\s]{0,64}:)?[^@\s]{1,128}@[^/\s]{1,256}(?:/[0-9]{1,2})?`

---

### 58. `password_in_url` — Password Embedded in URL

Generic URL with embedded `user:password@host` credentials. Catches database URLs, API endpoints, and service connections not covered by specific patterns.

**Example:** `https://admin:s3cret@api.internal.example.com`

**Regex:** `(?:https?|ftp|amqps?|kafka)://[^:@\s]{1,64}:[^@\s]{3,128}@[^/\s]{1,256}`

---

### 59. `env_database_password` — Database Password in Environment Variable

Database password in a `.env` file or shell export. Matches variable names like `DB_PASSWORD`, `POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`.

**Example:** `POSTGRES_PASSWORD=s3cur3_p4ssw0rd!`

**Regex:** `(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)[\s]*[=][\s]*["']?[^\s"'#]{3,128}["']?`

---

### 60. `ssh_private_key` — SSH/RSA/EC Private Key

PEM-encoded private key block. Matches RSA, EC, DSA, ED25519, OPENSSH, and encrypted private keys.

**Example:**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygAAbB3cD4eF5
gBBjkKMYqRNQ6sYvFo64FtaRLRR5BdHEESmha49TM3xY7z
-----END RSA PRIVATE KEY-----
```

**Regex:** `-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s|ENCRYPTED\s)?PRIVATE\sKEY-----[\s\S]{50,5000}?-----END\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s|ENCRYPTED\s)?PRIVATE\sKEY-----`

---

## AI / LLM Providers (6 patterns)

### 61. `openai_api_key` — OpenAI API Key

OpenAI API key starting with `sk-` prefix. Covers both standard keys and project-scoped keys (`sk-proj-`). Grants access to GPT models, DALL-E, embeddings, and other OpenAI services.

**Example:** `sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234`

**Regex:** `sk-(?:proj-)?[a-zA-Z0-9]{32,}`

---

### 62. `anthropic_api_key` — Anthropic API Key

Anthropic API key with highly distinctive `sk-ant-` prefix. Grants access to Claude models.

**Example:** `sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901`

**Regex:** `sk-ant-[a-zA-Z0-9\-_]{32,}`

---

### 63. `cohere_api_key` — Cohere API Key

Cohere API key, a 40-character alphanumeric string. No distinctive prefix — relies on context keywords like `COHERE_API_KEY` for detection.

**Example:** `COHERE_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0`

**Regex:** `(?:COHERE_API_KEY|cohere.*api.*key|cohere.*key)[\s]*[=:"'\s]+[a-zA-Z0-9]{40}`

---

### 64. `huggingface_token` — HuggingFace Token

HuggingFace token with `hf_` prefix followed by 34+ alphanumeric characters. Grants access to HuggingFace models and datasets.

**Example:** `hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh`

**Regex:** `hf_[A-Za-z0-9]{34,}`

---

### 65. `replicate_api_token` — Replicate API Token

Replicate API token with `r8_` prefix followed by 36+ alphanumeric characters. Grants access to Replicate model inference.

**Example:** `r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`

**Regex:** `r8_[A-Za-z0-9]{36,}`

---

### 66. `groq_api_key` — Groq API Key

Groq API key with `gsk_` prefix followed by 52+ alphanumeric characters. Grants access to Groq LPU inference.

**Example:** `gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`

**Regex:** `gsk_[A-Za-z0-9]{52,}`

---

## Generic & Auth Tokens (5 patterns)

### 67. `jwt_token` — JSON Web Token (JWT)

JWT identified by the `eyJ` prefix (base64-encoded JSON header) and three dot-separated segments.

**Example:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`

**Regex:** `eyJ[A-Za-z0-9_-]{10,500}\.[A-Za-z0-9_-]{10,1000}\.[A-Za-z0-9_-]{10,500}`

---

### 68. `bearer_token` — Bearer Token in Authorization Header

Bearer token found in an Authorization header pattern. The token itself could be any format.

**Example:** `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123`

**Regex:** `(?:Authorization|authorization|AUTHORIZATION)[\s]*[:=][\s]*["']?Bearer\s+[A-Za-z0-9_\-.]{20,500}["']?`

---

### 69. `basic_auth_header` — Basic Auth Credentials in Header

Base64-encoded `username:password` in a Basic authorization header.

**Example:** `Authorization: Basic dXNlcjpwYXNzd29yZA==`

**Regex:** `(?:Authorization|authorization|AUTHORIZATION)[\s]*[:=][\s]*["']?Basic\s+[A-Za-z0-9+/]{8,256}={0,2}["']?`

---

### 70. `generic_api_key_env` — Generic API Key in Environment Variable

API key, secret key, or access token assigned in an environment variable. Catches patterns like `API_KEY=...`, `SECRET_KEY=...`, `ACCESS_TOKEN=...` that don't match a specific provider.

**Example:** `API_KEY=a1B2c3D4e5F6g7H8i9J0k1L2m3N4`

**Regex:** `(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|APP_SECRET|APP_KEY|PRIVATE_KEY|CLIENT_SECRET|ENCRYPTION_KEY|SIGNING_KEY|WEBHOOK_SECRET)[\s]*[=][\s]*["']?[A-Za-z0-9_\-/+=.]{16,256}["']?`

---

### 71. `generic_high_entropy` — Generic High-Entropy String

A long, high-entropy alphanumeric string near context keywords suggesting it may be a secret. Lowest-confidence catch-all pattern — requires Shannon entropy above 4.0 to survive scoring.

**Example:** `secret=a8Kj2mNp4qRs6tUv8wXy0zA2bC4dE6fG`

**Regex:** `(?:key|token|secret|password|credential|api_key|apikey|auth)[\s]*[=:"'\s]+[A-Za-z0-9_\-/+=]{32,256}`

---

## Summary by Category

| Category | Count | Severity Range |
|----------|-------|---------------|
| Cloud Providers | 15 | critical – high |
| Payment & Financial | 11 | critical – low |
| Version Control & CI/CD | 12 | critical – high |
| Communications & SaaS | 15 | critical – medium |
| Database & Infrastructure | 7 | critical – high |
| AI / LLM Providers | 6 | critical – high |
| Generic & Auth Tokens | 5 | high – low |
| **Total** | **71** | |
