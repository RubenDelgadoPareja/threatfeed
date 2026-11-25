from datetime import datetime
from io import StringIO

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatfeed.classification import MAX_VALUE_LENGTH
from threatfeed.config import Settings
from threatfeed.geoip import GeoInfo
from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.run import track_run
from threatfeed.models import (
    Indicator,
    IndicatorSource,
    IndicatorType,
    IngestStatus,
    IPEnrichment,
)


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


class IPStubIngestor(StubIngestor):
    feed = "ipstub"

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator:
        return ParsedIndicator(
            type=IndicatorType.IP,
            value=(row.get("value") or "").strip(),
            first_seen=now,
            last_seen=now,
            raw=dict(row),
        )


class FakeGeo:
    def lookup(self, ip: str) -> GeoInfo | None:
        return GeoInfo(country_code="ES", country_name="Spain", asn=123, as_org="Example Net")


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


def test_ingest_enriches_ips_when_geoip_is_configured(db_session: Session) -> None:
    ingestor = IPStubIngestor(db_session, Settings(_env_file=None), FakeGeo())

    with track_run(db_session, "ipstub") as run:
        ingestor.ingest_rows(StringIO('"value"\n"1.2.3.4"\n'), run)

    indicator = db_session.scalars(select(Indicator)).one()
    enrichment = db_session.get(IPEnrichment, indicator.id)
    assert enrichment is not None
    assert (enrichment.country_code, enrichment.asn) == ("ES", 123)
    assert run.indicators_new == 1


def test_values_above_the_api_limit_are_skipped(db_session: Session) -> None:
    ingestor = _ingestor(db_session)
    long_value = "a" * (MAX_VALUE_LENGTH + 1)
    body = '"value"\n' + "".join(f'"v{i}.example"\n' for i in range(20))
    body += f'"{long_value}"\n'

    with track_run(db_session, "stub") as run:
        ingestor.ingest_rows(StringIO(body), run)

    assert run.status == IngestStatus.SUCCEEDED
    assert (run.rows_read, run.rows_skipped) == (21, 1)
    assert run.indicators_new == 20
