"""PostgreSQL advisory locks so two workers cannot ingest the same feed concurrently."""

import hashlib
import logging

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def _lock_id(feed: str) -> int:
    """Stable signed 64-bit id from the feed name, shared by every process."""
    digest = hashlib.blake2b(feed.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big", signed=True)


def try_lock(session: Session, feed: str) -> bool:
    return bool(session.scalar(select(func.pg_try_advisory_lock(_lock_id(feed)))))


def release_lock(session: Session, feed: str) -> None:
    try:
        session.execute(select(func.pg_advisory_unlock(_lock_id(feed))))
    except SQLAlchemyError:
        # A broken connection releases its session-level locks when it closes.
        logger.warning("could not release the %s lock explicitly", feed)
