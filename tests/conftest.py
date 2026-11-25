from collections.abc import Iterator
from datetime import UTC, datetime

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from threatfeed.config import get_settings
from threatfeed.db.base import Base
from threatfeed.db.session import get_db
from threatfeed.main import app
from threatfeed.models import Indicator, IndicatorSource, IndicatorType

TEST_DB_SUFFIX = "_test"


@pytest.fixture
def client() -> Iterator[TestClient]:
    """HTTP client with no database override (health and other DB-free endpoints)."""
    # The `with` block runs the app lifespan (startup / shutdown) around each test.
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def test_engine() -> Iterator[Engine]:
    """Fresh schema in a dedicated database, created once per test session."""
    settings = get_settings()
    test_db = f"{settings.postgres_db}{TEST_DB_SUFFIX}"

    try:
        with psycopg.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            user=settings.postgres_user,
            password=settings.postgres_password,
            dbname="postgres",
            autocommit=True,
        ) as connection:
            exists = connection.execute(
                "select 1 from pg_database where datname = %s", (test_db,)
            ).fetchone()
            if not exists:
                connection.execute(sql.SQL("create database {}").format(sql.Identifier(test_db)))
    except psycopg.OperationalError as exc:
        pytest.skip(f"PostgreSQL is not reachable, skipping database tests: {exc}")

    engine = create_engine(make_url(settings.database_url).set(database=test_db))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(test_engine: Engine) -> Iterator[Session]:
    """One transaction per test, rolled back at the end; the API commits into a savepoint."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def api_client(db_session: Session) -> Iterator[TestClient]:
    """HTTP client whose `get_db` dependency returns the test transaction's session."""

    def override_get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


def utc(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 3, day, hour, tzinfo=UTC)


@pytest.fixture
def seeded_indicators(db_session: Session) -> list[Indicator]:
    """A URL with two sources, an IP and a domain, with distinct freshness."""
    url = Indicator(
        type=IndicatorType.URL,
        value="http://example.com/a",
        first_seen=utc(1),
        last_seen=utc(5),
        raw={"id": "1"},
    )
    url.sources = [
        IndicatorSource(feed="urlhaus", first_seen=utc(1), last_seen=utc(4)),
        IndicatorSource(feed="feodotracker", first_seen=utc(2), last_seen=utc(5)),
    ]
    ip = Indicator(
        type=IndicatorType.IP,
        value="1.2.3.4",
        first_seen=utc(2),
        last_seen=utc(6),
        raw={"id": "2"},
    )
    ip.sources = [IndicatorSource(feed="feodotracker", first_seen=utc(2), last_seen=utc(6))]
    domain = Indicator(
        type=IndicatorType.DOMAIN,
        value="evil.example",
        first_seen=utc(3),
        last_seen=utc(4),
        raw={"id": "3"},
    )
    domain.sources = [IndicatorSource(feed="urlhaus", first_seen=utc(3), last_seen=utc(4))]

    db_session.add_all([url, ip, domain])
    db_session.flush()
    return [url, ip, domain]
