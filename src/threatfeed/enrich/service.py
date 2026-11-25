"""Backfill loop, separated from the CLI so it can be tested with a fake lookup."""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatfeed.enrichment import upsert_ip_enrichment
from threatfeed.geoip import GeoLookup
from threatfeed.models import Indicator, IndicatorType

DEFAULT_BATCH_SIZE = 500


@dataclass
class BackfillReport:
    processed: int = 0
    enriched: int = 0
    missing: int = 0


def backfill(
    session: Session,
    geoip: GeoLookup,
    *,
    limit: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> BackfillReport:
    """Enrich existing IP indicators in id order, committing one batch at a time."""
    report = BackfillReport()
    last_id = uuid.UUID(int=0)

    while limit is None or report.processed < limit:
        remaining = batch_size if limit is None else min(batch_size, limit - report.processed)
        if remaining <= 0:
            break

        batch = session.scalars(
            select(Indicator)
            .where(Indicator.type == IndicatorType.IP, Indicator.id > last_id)
            .order_by(Indicator.id)
            .limit(remaining)
        ).all()
        if not batch:
            break

        for indicator in batch:
            info = geoip.lookup(indicator.value)
            if info is None:
                report.missing += 1
            else:
                upsert_ip_enrichment(session, indicator.id, info)
                report.enriched += 1
            report.processed += 1

        session.commit()
        last_id = batch[-1].id

    return report
