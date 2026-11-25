"""Persist the GeoIP fields for an IP indicator."""

import uuid

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from threatfeed.geoip import GeoInfo
from threatfeed.models import IPEnrichment


def upsert_ip_enrichment(session: Session, indicator_id: uuid.UUID, info: GeoInfo) -> None:
    """Insert or refresh the enrichment row; called at ingestion and by the backfill."""
    values = {
        "indicator_id": indicator_id,
        "country_code": info.country_code,
        "country_name": info.country_name,
        "asn": info.asn,
        "as_org": info.as_org,
        "enriched_at": func.now(),
    }
    statement = (
        pg_insert(IPEnrichment)
        .values(**values)
        .on_conflict_do_update(
            index_elements=[IPEnrichment.indicator_id],
            set_={key: value for key, value in values.items() if key != "indicator_id"},
        )
    )
    session.execute(statement)
