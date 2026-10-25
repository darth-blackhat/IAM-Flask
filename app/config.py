from functools import lru_cache

from typing import Annotated, Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    # OpenIAM deployment, e.g. https://iam.example.com (no trailing slash)
    openiam_base_url: str = "http://localhost:8080"
    # OAuth client registered in OpenIAM (Access Control > Authentication Providers)
    # with grant type "Client Credentials" and Basic client authentication.
    openiam_client_id: str = ""
    openiam_client_secret: SecretStr = SecretStr("")
    openiam_verify_tls: bool = True
    openiam_timeout_seconds: float = 30.0

    # Deployment-specific type ids used when the caller does not supply one.
    default_user_metadata_type_id: str | None = None
    default_email_type_id: str | None = None
    default_phone_type_id: str | None = None

    # Change detection: which entities to watch and where to send changes.
    sync_config_path: str = "sync.yaml"
    # Run sync cycles in the background while `iam serve` is up.
    sync_schedule: bool = False

    # Producer intake: source systems (HR, ...) pushing hires, terminations, statuses.
    producer_config_path: str = "producer.yaml"

    # Consumer (remote site): picks up the producer side's zips and applies them to the
    # OpenIAM configured above (OPENIAM_* at the remote site point at the remote OpenIAM).
    consumer_config_path: str = "consumer.yaml"
    # Where the consumer applies changes: this site's OpenIAM, or (site without OpenIAM)
    # Active Directory, using the zip's AD instructions and the `ad:` section of consumer.yaml.
    consumer_target: Literal["openiam", "ad"] = "openiam"

    # Web UIs (Flask): `iam web` (producer site) and `iam oversight` (consumer site).
    # First admin: created at start when no web user exists yet (then manage users in the UI).
    web_username: str = "admin"
    web_password: SecretStr = SecretStr("")
    # Signs the session cookies. Set it (same value on every instance of one UI); if empty a
    # random key is used and everyone is logged out when the service restarts.
    web_secret_key: SecretStr = SecretStr("")
    # Session cookies only over HTTPS (keep true behind the TLS proxy).
    web_cookie_secure: bool = True
    web_idle_minutes: int = 30
    web_session_hours: int = 12
    web_max_failures: int = 5
    web_lock_minutes: int = 15

    # This backend's own database (sync state, outbox, producer records) - never OpenIAM's.
    # Production: postgresql+psycopg://user:pass@host:5432/dbname
    database_url: str = "sqlite:///data/backend.db"
    # PostgreSQL schema for this backend's tables (created if missing).
    database_schema: str | None = "backend_iam"

    # Consumer service metrics listener (it has no HTTP API). Port 0 turns it off.
    consumer_metrics_host: str = "127.0.0.1"
    consumer_metrics_port: int = 9102

    # How often services pick up operator requests from the web UI (0: never).
    operator_poll_seconds: float = 5.0

    # Retention in days (0 = keep forever). Pending/dead events and current state are kept.
    retention_outbox_days: int = 90
    retention_runs_days: int = 180
    retention_activity_days: int = 365
    retention_audit_days: int = 730

    # Logging (loguru). LOG_JSON=true writes one JSON object per line for log shippers.
    log_level: str = "INFO"
    # Mask e-mail addresses and phone numbers in log messages.
    log_redact: bool = True
    log_json: bool = False
    log_file: str | None = None

    # Bootstrap API key with every scope (for the first setup and tests). Prefer named keys:
    # `iam apikey create`. Requests are always authenticated; there is no "auth off".
    backend_api_key: SecretStr = SecretStr("")
    # Only these source networks may call the API at all (comma-separated CIDRs; empty: any).
    api_allowed_cidrs: Annotated[list[str], NoDecode] = []
    # Reverse proxies whose X-Forwarded-For is believed (comma-separated CIDRs).
    trusted_proxies: Annotated[list[str], NoDecode] = []
    # Requests per minute per API key (0: unlimited).
    api_rate_per_minute: int = 600
    # Largest accepted request body.
    max_request_bytes: int = 25 * 1024 * 1024

    @field_validator("api_allowed_cidrs", "trusted_proxies", mode="before")
    @classmethod
    def _split(cls, v):
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
