"""Application settings, loaded from environment variables and `.env`."""

from functools import lru_cache
from urllib.parse import quote

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str = "threatfeed"
    postgres_password: str = "threatfeed"
    postgres_db: str = "threatfeed"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # Required only to ingest, so the API and the tests run without it. Get one at auth.abuse.ch.
    urlhaus_auth_key: str | None = Field(default=None, repr=False)
    # Export filename inside the URLhaus v2 files API. Restricted: the key goes in the same path.
    urlhaus_export: str = Field(default="recent.csv", pattern=r"^[a-z0-9_]+\.csv$")

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
