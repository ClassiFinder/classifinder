"""
ClassiFinder — Application Configuration

Loads settings from environment variables. All configuration lives here;
nothing else in the app should read os.environ directly.
"""

import os
from functools import lru_cache
from typing import List


class Settings:
    """Application settings loaded from environment variables."""

    # API key whitelist: comma-separated list of valid API keys.
    # Example: CLASSIFINDER_API_KEYS=ss_live_abc123,ss_test_xyz789
    api_keys: List[str]

    # Rate limit: max requests per minute per API key (free tier default).
    rate_limit_per_minute: int

    # Max payload size in bytes (free tier default: 256 KB).
    max_payload_bytes: int

    # App metadata
    app_version: str
    app_name: str

    def __init__(self) -> None:
        raw_keys = os.environ.get("CLASSIFINDER_API_KEYS", "")
        self.api_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

        self.rate_limit_per_minute = int(
            os.environ.get("CLASSIFINDER_RATE_LIMIT_PER_MINUTE", "60")
        )
        self.max_payload_bytes = int(
            os.environ.get("CLASSIFINDER_MAX_PAYLOAD_BYTES", str(256 * 1024))
        )
        self.app_version = os.environ.get("CLASSIFINDER_VERSION", "1.0.0")
        self.app_name = "ClassiFinder API"

        # Turso (optional — key provisioning disabled if absent)
        self.turso_database_url = os.environ.get("TURSO_DATABASE_URL", "")
        self.turso_auth_token = os.environ.get("TURSO_AUTH_TOKEN", "")
        self.turso_enabled = bool(self.turso_database_url and self.turso_auth_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (cached after first call)."""
    return Settings()
