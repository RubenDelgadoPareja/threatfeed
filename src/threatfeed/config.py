"""Application settings, loaded from environment variables and `.env`."""

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    postgres_user: str = "threatfeed"
    postgres_password: str = "threatfeed"
    postgres_db: str = "threatfeed"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # Required only to ingest, so the API and the tests run without it. Get one at auth.abuse.ch.
    # `URLHAUS_AUTH_KEY` is still accepted as the pre-ThreatFox name.
    abusech_auth_key: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("ABUSECH_AUTH_KEY", "URLHAUS_AUTH_KEY"),
    )
    # Export filename inside the URLhaus v2 files API. Restricted: the key goes in the same path.
    urlhaus_export: str = Field(default="recent.csv", pattern=r"^[a-z0-9_]+\.csv$")

    # Optional GeoIP databases (MaxMind GeoLite2 or DB-IP Lite). Absent means no enrichment.
    geoip_country_db: Path | None = None
    geoip_asn_db: Path | None = None

    # Celery broker and scheduling defaults (UTC).
    redis_url: str = "redis://localhost:6379/0"
    urlhaus_interval_minutes: int = Field(default=60, ge=1)
    threatfox_schedule_hour: int = Field(default=0, ge=0, le=23)
    threatfox_schedule_minute: int = Field(default=30, ge=0, le=59)

    @property
    def database_url(self) -> str:
        """SQLAlchemy DSN: postgresql+psycopg://user:password@host:port/db"""
        password = quote(self.postgres_password, safe="")
        return (
            f"postgresql+psycopg://{self.postgres_user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
