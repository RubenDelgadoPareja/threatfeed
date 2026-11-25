"""URLhaus CSV export ingestor: download, parse, normalize and upsert."""

import csv
import logging
import re
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx2
from sqlalchemy import func, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from threatfeed.config import Settings
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.normalize import normalize_url
from threatfeed.ingest.run import track_run
from threatfeed.models import Indicator, IndicatorSource, IndicatorType, IngestRun

logger = logging.getLogger(__name__)

FEED = "urlhaus"
# The auth key is part of the path: that is the only form this endpoint accepts (a header gets 404).
EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/{export}"
REQUIRED_COLUMNS = {"url", "dateadded"}
BATCH_SIZE = 500
# A format change must not look like a healthy run that silently discarded half the feed.
MAX_SKIPPED_RATIO = 0.10
SKIP_SAMPLE_SIZE = 10
TIMEOUT_SECONDS = 30.0


class InvalidRow(ValueError):
    """One CSV row cannot be turned into an indicator; it is skipped and counted."""


@dataclass(frozen=True)
class ParsedIndicator:
    url: str
    first_seen: datetime
    last_seen: datetime
    raw: dict[str, Any]


def redact_url(url: str) -> str:
    """Hide the auth key before a URL reaches a log line or an error message."""
    return re.sub(r"(/exports/)[^/]+(/|$)", r"\1***\2", url)


def export_url(auth_key: str, export: str) -> str:
    """Build the export URL, percent-encoding the key so it cannot alter the path."""
    return EXPORT_URL.format(auth_key=quote(auth_key, safe=""), export=export)


@contextmanager
def _quiet_http_logs() -> Iterator[None]:
    """httpx2 logs every request URL at INFO, and this one carries the auth key.

    Process-wide and not thread-safe, which matches the current model: one ingest run per
    process. A future in-process worker pool would need its own logging policy.
    """
    http_logger = logging.getLogger("httpx2")
    previous = http_logger.level
    http_logger.setLevel(max(previous, logging.WARNING))
    try:
        yield
    finally:
        http_logger.setLevel(previous)


def parse_utc(value: str) -> datetime:
    """Parse URLhaus timestamps, which are UTC and may carry a ` UTC` suffix."""
    cleaned = value.strip().removesuffix("UTC").strip()
    if not cleaned:
        raise InvalidRow("empty timestamp")

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    raise InvalidRow(f"unparseable timestamp: {value!r}")


def parse_row(row: dict[str, str | None], now: datetime) -> ParsedIndicator:
    """Normalize one CSV row. Raises `InvalidRow` (or `InvalidUrl`) when it is unusable."""
    raw_url = (row.get("url") or "").strip()
    if not raw_url:
        raise InvalidRow("missing url")
    value = normalize_url(raw_url)

    first_seen = min(parse_utc(row.get("dateadded") or ""), now)
    last_online_raw = (row.get("last_online") or "").strip()
    last_seen = parse_utc(last_online_raw) if last_online_raw else first_seen
    last_seen = min(max(last_seen, first_seen), now)

    return ParsedIndicator(url=value, first_seen=first_seen, last_seen=last_seen, raw=dict(row))


def iter_rows(stream: Iterable[str]) -> Iterator[dict[str, str | None]]:
    """Yield data rows, ignoring comment/blank lines and validating the header once."""
    reader = csv.DictReader(_data_lines(stream))
    if reader.fieldnames is None:
        raise IngestError("feed is empty")

    reader.fieldnames = [name.strip() for name in reader.fieldnames]
    missing = REQUIRED_COLUMNS - set(reader.fieldnames)
    if missing:
        raise IngestError(f"feed is missing required columns: {sorted(missing)}")

    yield from reader


def _data_lines(stream: Iterable[str]) -> Iterator[str]:
    for line in stream:
        # A BOM would otherwise become part of the first header name.
        line = line.lstrip("\ufeff")
        if line.lstrip().startswith("#") or not line.strip():
            continue
        yield line


class URLHausIngestor:
    """Consume one URLhaus CSV export into the indicator store."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def run(self, *, limit: int | None = None) -> None:
        if not self.settings.urlhaus_auth_key:
            raise IngestError(
                "URLHAUS_AUTH_KEY is not configured; get a free key at https://auth.abuse.ch/"
            )

        url = self._export_url()
        logger.info("downloading %s", redact_url(url))

        with track_run(self.session, FEED) as run, self._download(url) as stream:
            self.ingest_stream(stream, run, limit=limit)

        logger.info(
            "ingested %s: %d read, %d skipped, %d new, %d updated",
            FEED,
            run.rows_read,
            run.rows_skipped,
            run.indicators_new,
            run.indicators_updated,
        )

    def ingest_stream(
        self, stream: Iterable[str], run: IngestRun, *, limit: int | None = None
    ) -> None:
        """Parse and upsert an already open CSV stream. Split out so tests can feed a fixture."""
        now = datetime.now(UTC)
        batch: list[ParsedIndicator] = []
        skipped_samples = 0

        for row_number, row in enumerate(iter_rows(stream), start=1):
            if limit is not None and row_number > limit:
                break
            run.rows_read += 1

            try:
                batch.append(parse_row(row, now))
            except ValueError as exc:
                run.rows_skipped += 1
                if skipped_samples < SKIP_SAMPLE_SIZE:
                    skipped_samples += 1
                    logger.warning("skipping row %d: %s", row_number, exc)

            if len(batch) >= BATCH_SIZE:
                self._store(run, batch)
                batch.clear()
                self._check_skip_ratio(run)

        if batch:
            self._store(run, batch)

        if run.rows_read == 0:
            raise IngestError("feed has no data rows")
        self._check_skip_ratio(run)

    def _export_url(self) -> str:
        return export_url(self.settings.urlhaus_auth_key or "", self.settings.urlhaus_export)

    @contextmanager
    def _download(self, url: str) -> Iterator[Iterable[str]]:
        try:
            with (
                _quiet_http_logs(),
                httpx2.Client(
                    follow_redirects=True, timeout=httpx2.Timeout(TIMEOUT_SECONDS)
                ) as client,
                client.stream("GET", url) as response,
            ):
                if response.status_code != 200:
                    raise IngestError(f"URLhaus export returned HTTP {response.status_code}")

                content_type = response.headers.get("content-type", "").lower()
                if content_type.startswith(("application/json", "text/html")):
                    raise IngestError(f"URLhaus returned {content_type!r}, not a CSV export")

                # Line-by-line, never buffering the whole export in memory.
                yield response.iter_lines()
        except httpx2.HTTPError as exc:
            # Network errors embed the request URL, key included; never chain the original.
            raise IngestError(f"URLhaus request failed: {redact_url(str(exc))}") from None

    def _store(self, run: IngestRun, batch: list[ParsedIndicator]) -> None:
        for item in batch:
            indicator_id, inserted = self._upsert_indicator(item)
            self._upsert_source(indicator_id, item)
            if inserted:
                run.indicators_new += 1
            else:
                run.indicators_updated += 1
        self.session.commit()

    def _upsert_indicator(self, item: ParsedIndicator) -> tuple[uuid.UUID, bool]:
        insert = pg_insert(Indicator).values(
            type=IndicatorType.URL,
            value=item.url,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            raw=item.raw,
        )
        statement = insert.on_conflict_do_update(
            index_elements=[Indicator.type, Indicator.value],
            set_={
                # LEAST/GREATEST keep the earliest first_seen and the latest last_seen ever seen.
                "first_seen": func.least(Indicator.first_seen, insert.excluded.first_seen),
                "last_seen": func.greatest(Indicator.last_seen, insert.excluded.last_seen),
                "raw": insert.excluded.raw,
            },
        ).returning(Indicator.id, literal_column("(xmax = 0)").label("inserted"))

        indicator_id, inserted = self.session.execute(statement).one()
        return indicator_id, inserted

    def _upsert_source(self, indicator_id: uuid.UUID, item: ParsedIndicator) -> None:
        insert = pg_insert(IndicatorSource).values(
            indicator_id=indicator_id,
            feed=FEED,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
        )
        statement = insert.on_conflict_do_update(
            index_elements=[IndicatorSource.indicator_id, IndicatorSource.feed],
            set_={
                "first_seen": func.least(IndicatorSource.first_seen, insert.excluded.first_seen),
                "last_seen": func.greatest(IndicatorSource.last_seen, insert.excluded.last_seen),
            },
        )
        self.session.execute(statement)

    @staticmethod
    def _check_skip_ratio(run: IngestRun) -> None:
        if run.rows_skipped > run.rows_read * MAX_SKIPPED_RATIO:
            raise IngestError(
                f"discarded {run.rows_skipped} of {run.rows_read} rows "
                f"(more than {MAX_SKIPPED_RATIO:.0%}); the feed format probably changed"
            )
