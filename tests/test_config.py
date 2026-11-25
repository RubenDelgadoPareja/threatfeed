import pytest
from pydantic import ValidationError

from threatfeed.config import Settings

# `_env_file=None` keeps the tests independent from whatever `.env` the developer has locally.


def test_database_url_from_parts() -> None:
    settings = Settings(
        _env_file=None,
        postgres_user="u",
        postgres_password="p",
        postgres_host="db",
        postgres_port=5433,
        postgres_db="tf",
    )

    assert settings.database_url == "postgresql+psycopg://u:p@db:5433/tf"


def test_database_url_escapes_password() -> None:
    # "@", ":" and "/" are reserved inside a URL: unescaped, they break DSN parsing.
    settings = Settings(_env_file=None, postgres_password="p@ss:w/rd")

    assert (
        settings.database_url
        == "postgresql+psycopg://threatfeed:p%40ss%3Aw%2Frd@localhost:5432/threatfeed"
    )


def test_urlhaus_export_cannot_escape_the_export_path() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, urlhaus_export="../../etc/passwd")
