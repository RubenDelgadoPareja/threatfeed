"""Application settings, loaded from environment variables and `.env`."""

from functools import lru_cache
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str = "threatfeed"
    postgres_password: str = "threatfeed"
    postgres_db: str = "threatfeed"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    @property
    def database_url(self) -> str:
        """SQLAlchemy DSN: postgresql+psycopg://user:password@host:port/db"""
        return f"postgresql+psycopg://{self.postgres_user}:{quote_plus(self.postgres_password)}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"  # EXERCISE A


@lru_cache
def get_settings() -> Settings:
    return Settings()
