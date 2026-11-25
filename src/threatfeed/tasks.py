"""Celery tasks: thin wrappers over the shared, locked ingestion runner."""

import logging

from sqlalchemy.exc import OperationalError

from threatfeed.celery_app import app
from threatfeed.config import get_settings
from threatfeed.db.session import get_session_factory
from threatfeed.geoip import GeoIP
from threatfeed.ingest.errors import RateLimitedError, RetryableIngestError
from threatfeed.ingest.runner import run_feed

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


@app.task(bind=True, name="threatfeed.ingest_feed", max_retries=MAX_RETRIES)
def ingest_feed(self, feed: str, limit: int | None = None) -> str:
    settings = get_settings()
    geoip = None
    try:
        geoip = GeoIP.from_settings(settings)
        with get_session_factory()() as session:
            started = run_feed(session, feed, settings, geoip, limit=limit)

        if not started:
            logger.warning("%s is already running; task skipped", feed)
            return "locked"
        return "ok"
    except RateLimitedError as exc:
        logger.warning("%s is rate limited: %s", feed, exc)
        return "rate-limited"
    except (RetryableIngestError, OperationalError) as exc:
        countdown = min(30 * 2**self.request.retries, 900)
        raise self.retry(exc=exc, countdown=countdown) from None
    finally:
        if geoip is not None:
            geoip.close()
