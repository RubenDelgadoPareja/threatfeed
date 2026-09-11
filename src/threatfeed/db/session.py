"""Engine and session factory. Everything here is lazy: importing it needs no database."""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from threatfeed.config import get_settings


@lru_cache
def get_engine() -> Engine:
    # INTERVIEW: pool_pre_ping sends a cheap "SELECT 1" before reusing a pooled connection,
    # so one killed by the database or the network is replaced instead of failing mid-request.
    return create_engine(get_settings().database_url, pool_pre_ping=True)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    # expire_on_commit=False: objects stay readable after commit (endpoints return them).
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one Session per request, always closed (~ Rails around_action)."""
    with get_session_factory()() as db:
        yield db
