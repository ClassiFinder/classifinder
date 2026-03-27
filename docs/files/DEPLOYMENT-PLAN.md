# Deployment Plan — ClassiFinder

## What This Document Is

Step-by-step plan for deploying ClassiFinder to two platforms: Fly.io (primary) and AWS Lambda (secondary). Execute these in order. Run all tests before and after each major step.

---

## Prerequisites

Before starting, confirm:

```bash
python -m pytest tests/ -v    # all 57 tests pass
docker build -t classifinder . # Docker image builds
docker run -e CLASSIFINDER_API_KEYS="ss_test_000000000000000000000000000000000000000000" -p 8000:8000 classifinder
curl http://localhost:8000/v1/health   # returns healthy
```

If any of these fail, fix them before proceeding.

---

## Part 1: Fly.io Deployment (Primary)

### 1.1 Install flyctl

```bash
curl -L https://fly.io/install.sh | sh
fly auth login
```

### 1.2 Create fly.toml

Create `fly.toml` in the project root. This is the Fly.io configuration file.

```toml
app = 'classifinder'
primary_region = 'sjc'

[build]
  dockerfile = "Dockerfile"

[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = 'stop'
  auto_start_machines = true
  min_machines_running = 0

[checks]
  [checks.health]
    type = "http"
    port = 8000
    path = "/v1/health"
    interval = "30s"
    timeout = "5s"
    grace_period = "10s"

[[vm]]
  size = 'shared-cpu-1x'
  memory = '256mb'
```

Key decisions in this config:
- `auto_stop_machines = 'stop'` + `min_machines_running = 0` enables scale-to-zero. The machine stops when idle, keeping costs near $0.
- `primary_region = 'sjc'` is San Jose (closest to SF). Change if deploying elsewhere.
- `shared-cpu-1x` with 256MB RAM is sufficient — the app uses ~80MB at rest and regex scanning is CPU-light.
- Health check hits `/v1/health` which requires no auth.

### 1.3 Set Secrets

Generate a real API key for production use. Keys must be 48 characters with the `ss_live_` prefix:

```bash
# Generate a production key (example — use your own)
# Format: ss_live_ + 40 random alphanumeric chars
fly secrets set CLASSIFINDER_API_KEYS="ss_live_<your_40_char_random_string_here>"
fly secrets set CLASSIFINDER_RATE_LIMIT_PER_MINUTE="60"
fly secrets set CLASSIFINDER_MAX_PAYLOAD_BYTES="262144"
```

Do NOT set these as plain environment variables in fly.toml — use `fly secrets` so they're encrypted.

### 1.4 Deploy

```bash
fly launch --no-deploy   # creates the app, skips initial deploy
fly deploy               # builds Docker image remotely, deploys
```

### 1.5 Verify

```bash
# Health check (no auth required)
curl https://classifinder.fly.dev/v1/health

# Scan test (with auth)
curl -X POST https://classifinder.fly.dev/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_live_<your_key>" \
  -d '{"text": "AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284"}'

# Redact test
curl -X POST https://classifinder.fly.dev/v1/redact \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_live_<your_key>" \
  -d '{"text": "STRIPE_KEY=sk_live_51H3aKLkdsjfhDKJSH38djfhksd"}'

# Types list
curl https://classifinder.fly.dev/v1/types \
  -H "X-API-Key: ss_live_<your_key>"
```

All four should return 200 with correct JSON responses.

### 1.6 Custom Domain

```bash
fly certs create yourdomain.com
```

Fly will give you IP addresses. Create DNS records:
- A record → the IPv4 address Fly provides
- AAAA record → the IPv6 address Fly provides

TLS certificate is provisioned automatically within minutes.

### 1.7 Monitoring

```bash
fly logs          # stream live logs (should show only metadata, never request bodies)
fly status        # machine state
fly dashboard     # open web dashboard
```

Verify the logs output matches the safe metadata format from `app/middleware/logging.py` — request_id, api_key_hash, timestamp, method, endpoint, input_size_bytes, finding_count, response_time_ms, status_code. Nothing else.

---

## Part 2: AWS Lambda Deployment (Secondary)

### 2.1 Modify Dockerfile for Lambda

Create a separate `Dockerfile.lambda` in the project root. Do NOT modify the original Dockerfile.

```dockerfile
FROM python:3.12-slim

# Install Lambda Web Adapter
COPY --from=public.ecr.aws/awsguru/aws-lambda-web-adapter:0.8.4 /lambda-adapter /opt/extensions/lambda-adapter

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/

# Lambda Web Adapter expects the app on port 8080 by default
ENV PORT=8080
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

The Lambda Web Adapter binary sits in `/opt/extensions/` and automatically translates Lambda invoke events into HTTP requests to your Uvicorn server. Zero code changes to the app.

### 2.2 Create ECR Repository

```bash
aws ecr create-repository --repository-name classifinder --region us-west-2
```

### 2.3 Build and Push Docker Image

```bash
# Get the ECR login
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin <account_id>.dkr.ecr.us-west-2.amazonaws.com

# Build for Lambda
docker build -f Dockerfile.lambda -t classifinder-lambda .

# Tag and push
docker tag classifinder-lambda:latest <account_id>.dkr.ecr.us-west-2.amazonaws.com/classifinder:latest
docker push <account_id>.dkr.ecr.us-west-2.amazonaws.com/classifinder:latest
```

### 2.4 Create Lambda Function

```bash
# Create execution role (one-time)
aws iam create-role \
  --role-name classifinder-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name classifinder-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Create the function
aws lambda create-function \
  --function-name classifinder \
  --package-type Image \
  --code ImageUri=<account_id>.dkr.ecr.us-west-2.amazonaws.com/classifinder:latest \
  --role arn:aws:iam::<account_id>:role/classifinder-lambda-role \
  --timeout 30 \
  --memory-size 256 \
  --environment "Variables={CLASSIFINDER_API_KEYS=ss_live_<your_key>,CLASSIFINDER_RATE_LIMIT_PER_MINUTE=60}"
```

### 2.5 Create Function URL (simplest public access)

```bash
aws lambda create-function-url-config \
  --function-name classifinder \
  --auth-type NONE

aws lambda add-permission \
  --function-name classifinder \
  --statement-id FunctionURLAllowPublicAccess \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE
```

This gives you a URL like `https://<id>.lambda-url.us-west-2.on.aws/`. The app handles its own auth via the X-API-Key middleware — Lambda's auth-type NONE is fine.

### 2.6 Verify

```bash
LAMBDA_URL="https://<id>.lambda-url.us-west-2.on.aws"

curl $LAMBDA_URL/v1/health

curl -X POST $LAMBDA_URL/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ss_live_<your_key>" \
  -d '{"text": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"}'
```

Note: The first request after deployment will have a cold start of 1-3 seconds. Subsequent requests should be fast.

### 2.7 Custom Domain (Optional, for later)

For a custom domain on Lambda, you'd set up API Gateway (HTTP API type) in front of the function URL, then attach a custom domain with an ACM certificate. This is more involved — skip for now and do it when/if you need the Lambda deployment as a production endpoint rather than a fallback.

---

## Part 3: Post-Deployment Verification Checklist

Run through this after both deployments are live:

```
[ ] Fly.io /v1/health returns 200
[ ] Fly.io /v1/scan detects AWS key with auth
[ ] Fly.io /v1/scan returns 401 without auth
[ ] Fly.io /v1/scan returns 401 with invalid key
[ ] Fly.io /v1/redact returns redacted text
[ ] Fly.io /v1/types returns 46 patterns
[ ] Fly.io logs show ONLY metadata (no request bodies, no secret values)
[ ] Fly.io rate limit headers present on responses
[ ] Lambda /v1/health returns 200
[ ] Lambda /v1/scan detects Stripe key with auth
[ ] Lambda cold start is under 3 seconds
[ ] Lambda warm request is under 500ms total
```

---

## Part 4: Files to Create

Summary of new files this plan adds to the project:

| File | Purpose |
|------|---------|
| `fly.toml` | Fly.io deployment configuration |
| `Dockerfile.lambda` | Lambda-specific Dockerfile with Web Adapter |
| `.dockerignore` | Exclude tests, docs, .git from Docker builds |
| `.gitignore` | Standard Python gitignore if not already present |

### .dockerignore

Create this in the project root:

```
.git
.gitignore
__pycache__
*.pyc
tests/
*.md
.pytest_cache
fly.toml
Dockerfile.lambda
```

### .gitignore

Create this if it doesn't exist:

```
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
dist/
build/
.env
.env.*
```

---

## What NOT to Do

- Do not modify `app/` code for deployment. The app runs identically on both platforms.
- Do not put API keys in fly.toml, Dockerfile, or any committed file. Use `fly secrets` and Lambda environment variables only.
- Do not enable API Gateway request logging with full payloads on Lambda. The default (CloudWatch logs from your app's stdout) is correct.
- Do not add a reverse proxy (nginx, caddy) in front of Uvicorn. Both Fly.io and Lambda handle TLS termination and proxying.
- Do not set `min_machines_running = 1` on Fly.io unless you want to pay for an always-on machine. Scale-to-zero is correct for MVP traffic.
