FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Copy application code
COPY app/ app/

EXPOSE 8000

ENV CLASSIFINDER_API_KEYS=""
ENV CLASSIFINDER_RATE_LIMIT_PER_MINUTE="60"
ENV CLASSIFINDER_MAX_PAYLOAD_BYTES="262144"
ENV CLASSIFINDER_VERSION="1.0.0"

RUN adduser --disabled-password --no-create-home appuser
USER appuser

# --workers 4: four uvicorn worker processes to bypass the GIL.
# 2026-04-26: bumping from 2 → 4 to test whether shared-cpu-1x is CPU-bound
# or whether the GIL was the only blocker. With workers=2 the cfsniff
# baseline measurement showed wall time at w=8 dropping 1.69× (3.26s → 1.93s),
# confirming GIL was the bottleneck. workers=4 probes whether the curve
# continues — if yes, GIL was the full story; if no, CPU-shared is now the
# floor and we should bump the Fly machine size.
# Memory: each worker is ~50 MB, so 4 workers ≈ 200 MB out of the 256 MB
# budget. Tight. Watch fly logs for OOM after deploy.
# CAVEAT (still): in-memory rate limiter is per-process — each key's
# effective rate limit is now 4× CLASSIFINDER_RATE_LIMIT_PER_MINUTE. If
# precise per-key rate limiting is required, switch to a shared store.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
