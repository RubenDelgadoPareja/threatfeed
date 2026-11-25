"""Shared ingestion flow: download hook, row parsing, batches, counters and upsert."""

import logging
import uuid
from collections.abc import Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import func, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from threatfeed.config import Settings
from threatfeed.ingest.csv import iter_rows
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.run import track_run
from threatfeed.models import Indicator, IndicatorSource, IndicatorType, IngestRun

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedIndicator:
    type: IndicatorType
    value: str
    first_seen: datetime
    last_seen: datetime
    raw: dict[str, Any]


class BaseIngestor:
    """One feed. Subclasses provide the download and the row-to-indicator mapping.

    Everything else — comment-prefixed CSV header, batching, idempotent upsert, counters,
    provenance and the skip-ratio guard — is identical across feeds and lives here.
    """

    feed: ClassVar[str]
    required_columns: ClassVar[set[str]]
    batch_size: ClassVar[int] = 500
    max_unexpected_ratio: ClassVar[float] = 0.10
    skip_sample_size: ClassVar[int] = 10

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def validate(self) -> None:
        """Fail before opening a run when the feed cannot be consumed (e.g. missing key)."""

    def describe_source(self) -> str:
        """What to log as the source; must be safe to print (no keys)."""
        return self.feed

    def open_rows(self) -> AbstractContextManager[Iterable[str]]:
        raise NotImplementedError

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
        """Return an indicator, or None to skip the row (e.g. an unsupported IOC type)."""
        raise NotImplementedError

    def run(self, *, limit: int | None = None) -> None:
        self.validate()
        logger.info("reading %s", self.describe_source())

        with track_run(self.session, self.feed) as run, self.open_rows() as rows:
            self.ingest_rows(rows, run, limit=limit)

        logger.info(
            "ingested %s: %d read, %d skipped, %d new, %d updated",
            self.feed,
            run.rows_read,
            run.rows_skipped,
            run.indicators_new,
            run.indicators_updated,
        )

    def ingest_rows(
        self, stream: Iterable[str], run: IngestRun, *, limit: int | None = None
    ) -> None:
        now = datetime.now(UTC)
        batch: list[ParsedIndicator] = []
        skipped_samples = 0
        unexpected_skips = 0

        for row_number, row in enumerate(iter_rows(stream, self.required_columns), start=1):
            if limit is not None and row_number > limit:
                break
            run.rows_read += 1

            reason = "unsupported row"
            try:
                item = self.parse_row(row, now)
                if item is not None:
                    batch.append(item)
                else:
                    reason = "unsupported indicator type"
            except ValueError as exc:
                item = None
                unexpected_skips += 1
                reason = str(exc)

            if item is None:
                run.rows_skipped += 1
                if skipped_samples < self.skip_sample_size:
                    skipped_samples += 1
                    logger.warning("skipping row %d: %s", row_number, reason)

            if len(batch) >= self.batch_size:
                self._store(run, batch)
                batch.clear()
                self._check_unexpected_ratio(run, unexpected_skips)

        if batch:
            self._store(run, batch)

        if run.rows_read == 0:
            raise IngestError("feed has no data rows")
        self._check_unexpected_ratio(run, unexpected_skips)

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
            type=item.type,
            value=item.value,
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
            feed=self.feed,
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

    def _check_unexpected_ratio(self, run: IngestRun, unexpected: int) -> None:
        """Known unsupported types may be skipped; malformed rows signal a format change."""
        if unexpected > run.rows_read * self.max_unexpected_ratio:
            raise IngestError(
                f"discarded {unexpected} malformed rows of {run.rows_read} "
                f"(more than {self.max_unexpected_ratio:.0%}); "
                "the feed format probably changed"
            )
