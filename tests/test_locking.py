from sqlalchemy import Engine
from sqlalchemy.orm import Session

from threatfeed.ingest.locking import release_lock, try_lock


def test_advisory_lock_is_exclusive(test_engine: Engine) -> None:
    with test_engine.connect() as first, test_engine.connect() as second:
        first_session = Session(bind=first)
        second_session = Session(bind=second)
        try:
            assert try_lock(first_session, "urlhaus") is True
            assert try_lock(second_session, "urlhaus") is False

            release_lock(first_session, "urlhaus")
            assert try_lock(second_session, "urlhaus") is True
        finally:
            release_lock(second_session, "urlhaus")
            first_session.close()
            second_session.close()
