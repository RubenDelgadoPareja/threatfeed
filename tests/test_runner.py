from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from threatfeed.config import Settings
from threatfeed.ingest import runner
from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.locking import release_lock, try_lock
from threatfeed.models import IndicatorType, IngestRun, IngestStatus


class StubIngestor(BaseIngestor):
    feed = "stub"
    required_columns = {"value"}

    @contextmanager
    def open_rows(self) -> Iterator[Iterable[str]]:
        yield ['"value"\n', '"a.example"\n']

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator:
        return ParsedIndicator(
            type=IndicatorType.DOMAIN,
            value=(row.get("value") or "").strip(),
            first_seen=now,
            last_seen=now,
            raw=dict(row),
        )


@pytest.fixture(autouse=True)
def register_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(runner.FEEDS, "stub", StubIngestor)


def test_run_feed_runs_under_the_lock(db_session: Session) -> None:
    started = runner.run_feed(db_session, "stub", Settings(_env_file=None), None)

    assert started is True
    run = db_session.scalars(select(IngestRun)).one()
    assert run.feed == "stub"
    assert run.status == IngestStatus.SUCCEEDED
    assert run.indicators_new == 1


def test_run_feed_skips_when_another_run_holds_the_lock(
    db_session: Session, test_engine: Engine
) -> None:
    with test_engine.connect() as other:
        other_session = Session(bind=other)
        try:
            assert try_lock(other_session, "stub") is True
            started = runner.run_feed(db_session, "stub", Settings(_env_file=None), None)
            assert started is False
        finally:
            release_lock(other_session, "stub")
            other_session.close()

    assert db_session.scalar(select(func.count()).select_from(IngestRun)) == 0


def test_unknown_feed_is_rejected(db_session: Session) -> None:
    with pytest.raises(IngestError, match="unknown feed"):
        runner.run_feed(db_session, "nope", Settings(_env_file=None), None)
