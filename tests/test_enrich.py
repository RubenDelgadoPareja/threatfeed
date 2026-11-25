from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatfeed.enrich.service import backfill
from threatfeed.geoip import GeoInfo
from threatfeed.models import Indicator, IndicatorType, IPEnrichment


class FakeGeo:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def lookup(self, ip: str) -> GeoInfo | None:
        self.seen.append(ip)
        if ip.startswith("10."):
            return None
        return GeoInfo(country_code="ES", country_name="Spain", asn=123, as_org="Example Net")


def _ip(session: Session, value: str) -> Indicator:
    now = datetime.now(UTC)
    indicator = Indicator(type=IndicatorType.IP, value=value, first_seen=now, last_seen=now, raw={})
    session.add(indicator)
    session.flush()
    return indicator


def test_backfill_enriches_ips_and_counts_misses(db_session: Session) -> None:
    enriched = _ip(db_session, "1.2.3.4")
    missing = _ip(db_session, "10.0.0.1")
    db_session.add(
        Indicator(
            type=IndicatorType.DOMAIN,
            value="example.com",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            raw={},
        )
    )
    db_session.flush()

    report = backfill(db_session, FakeGeo())

    assert (report.processed, report.enriched, report.missing) == (2, 1, 1)
    row = db_session.get(IPEnrichment, enriched.id)
    assert row is not None
    assert (row.country_code, row.country_name, row.asn, row.as_org) == (
        "ES",
        "Spain",
        123,
        "Example Net",
    )
    assert db_session.get(IPEnrichment, missing.id) is None
    assert db_session.scalar(select(func.count()).select_from(IPEnrichment)) == 1


def test_backfill_is_idempotent(db_session: Session) -> None:
    indicator = _ip(db_session, "1.2.3.4")

    backfill(db_session, FakeGeo())
    backfill(db_session, FakeGeo())

    assert db_session.scalar(select(func.count()).select_from(IPEnrichment)) == 1
    assert db_session.get(IPEnrichment, indicator.id) is not None


def test_backfill_honors_the_limit(db_session: Session) -> None:
    for value in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        _ip(db_session, value)

    report = backfill(db_session, FakeGeo(), limit=2)

    assert report.processed == 2
    assert report.enriched == 2
    assert db_session.scalar(select(func.count()).select_from(IPEnrichment)) == 2
