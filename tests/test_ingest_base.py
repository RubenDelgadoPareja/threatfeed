from datetime import datetime
from io import StringIO

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatfeed.config import Settings
from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.run import track_run
from threatfeed.models import Indicator, IndicatorSource, IndicatorType, IngestStatus


class StubIngestor(BaseIngestor):
    feed = "stub"
    required_columns = {"value"}

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
        value = (row.get("value") or "").strip()
        if value == "skip":
            return None
        if not value:
            raise InvalidRow("empty value")
        return ParsedIndicator(
            type=IndicatorType.DOMAIN,
            value=value,
            first_seen=now,
            last_seen=now,
            raw=dict(row),
        )


def _ingestor(session: Session) -> StubIngestor:
    return StubIngestor(session, Settings(_env_file=None))


def test_ingest_rows_stores_indicators_and_provenance(db_session: Session) -> None:
    ingestor = _ingestor(db_session)

    with track_run(db_session, "stub") as run:
        ingestor.ingest_rows(StringIO('"value"\n"a.example"\n"b.example"\n'), run)

    assert run.status == IngestStatus.SUCCEEDED
    assert (run.rows_read, run.rows_skipped) == (2, 0)
    assert (run.indicators_new, run.indicators_updated) == (2, 0)
    assert db_session.scalar(select(func.count()).select_from(Indicator)) == 2
    assert db_session.scalar(select(func.count()).select_from(IndicatorSource)) == 2


def test_ingest_rows_is_idempotent(db_session: Session) -> None:
    ingestor = _ingestor(db_session)

    with track_run(db_session, "stub") as first:
        ingestor.ingest_rows(StringIO('"value"\n"a.example"\n'), first)
    with track_run(db_session, "stub") as second:
        ingestor.ingest_rows(StringIO('"value"\n"a.example"\n"c.example"\n'), second)

    assert (first.indicators_new, first.indicators_updated) == (1, 0)
    assert (second.indicators_new, second.indicators_updated) == (1, 1)
    assert db_session.scalar(select(func.count()).select_from(Indicator)) == 2


def test_too_many_skipped_rows_fail_the_run(db_session: Session) -> None:
    ingestor = _ingestor(db_session)

    with pytest.raises(IngestError, match="malformed"), track_run(db_session, "stub") as run:
        ingestor.ingest_rows(StringIO('"value"\n"a.example"\n""\n"b.example"\n'), run)

    assert run.status == IngestStatus.FAILED
    assert run.error is not None and "malformed" in run.error


def test_expected_skips_do_not_fail_the_run(db_session: Session) -> None:
    ingestor = _ingestor(db_session)

    with track_run(db_session, "stub") as run:
        ingestor.ingest_rows(StringIO('"value"\n"a.example"\n"skip"\n"b.example"\n'), run)

    assert run.status == IngestStatus.SUCCEEDED
    assert (run.rows_read, run.rows_skipped) == (3, 1)
    assert run.indicators_new == 2
