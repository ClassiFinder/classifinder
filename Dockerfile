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

# --workers 2: two uvicorn worker processes to bypass the GIL on CPU-bound
# regex matching. Single-worker default serializes all concurrent requests
# through one Python process; cfsniff baseline measurement on 2026-04-26
# showed throughput floored at ~1.7 MB/s on shared-cpu-1x regardless of
# client-side concurrency. Each worker is ~50 MB, so 2 workers fits
# comfortably in the 256 MB budget.
# CAVEAT: in-memory rate limiter is per-process — each key's effective
# rate limit is now 2× CLASSIFINDER_RATE_LIMIT_PER_MINUTE. If precise
# per-key rate limiting is required, switch to a shared store (Redis/Turso).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
