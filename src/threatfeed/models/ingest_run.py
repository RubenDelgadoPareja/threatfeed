"""Audit trail of every ingestion: one row per attempt, written before the feed is touched."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatfeed.db.base import Base
from threatfeed.models.enums import IngestStatus

IngestStatusEnum = Enum(
    IngestStatus,
    name="ingest_status",
    values_callable=lambda enum: [member.value for member in enum],
    validate_strings=True,
)


class IngestRun(Base):
    """Counters and outcome of one feed ingestion.

    A run that dies mid-flight leaves a `running` row with no `finished_at`, which is exactly
    the signal you want when a scheduled job silently stops working.
    """

    __tablename__ = "ingest_runs"
    __table_args__ = (Index("ix_ingest_runs_feed_started_at", "feed", "started_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()")
    )
    # Feed names come from the ingestor registry in code, so a plain string validated by the
    # application; an enum here would force a migration just to add a feed.
    feed: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[IngestStatus] = mapped_column(
        IngestStatusEnum, nullable=False, default=IngestStatus.RUNNING
    )
    rows_read: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    rows_skipped: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    indicators_new: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    indicators_updated: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
