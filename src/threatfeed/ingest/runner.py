"""Feed registry and the locked run shared by the CLI and Celery."""

from sqlalchemy.orm import Session

from threatfeed.config import Settings
from threatfeed.geoip import GeoLookup
from threatfeed.ingest.base import BaseIngestor
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.locking import release_lock, try_lock
from threatfeed.ingest.threatfox import ThreatFoxIngestor
from threatfeed.ingest.urlhaus import URLHausIngestor

FEEDS: dict[str, type[BaseIngestor]] = {
    "threatfox": ThreatFoxIngestor,
    "urlhaus": URLHausIngestor,
}


def run_feed(
    session: Session,
    feed: str,
    settings: Settings,
    geoip: GeoLookup | None,
    *,
    limit: int | None = None,
) -> bool:
    """Run one feed under its advisory lock. Returns False when another run holds it."""
    ingestor = FEEDS.get(feed)
    if ingestor is None:
        raise IngestError(f"unknown feed: {feed!r}")

    if not try_lock(session, feed):
        return False

    try:
        ingestor(session, settings, geoip).run(limit=limit)
    finally:
        release_lock(session, feed)
    return True
