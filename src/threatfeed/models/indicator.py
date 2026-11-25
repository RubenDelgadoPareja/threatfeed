"""IoC storage: one row per unique `(type, value)`, with per-feed provenance."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threatfeed.db.base import Base
from threatfeed.models.enums import IndicatorType

# `values_callable` makes PostgreSQL store `ip`, not the Python member name `IP`.
IndicatorTypeEnum = Enum(
    IndicatorType,
    name="indicator_type",
    values_callable=lambda enum: [member.value for member in enum],
    validate_strings=True,
)


class Indicator(Base):
    """A normalized observable. `(type, value)` is its identity across every feed."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicators_type_value"),
        CheckConstraint("value <> ''", name="ck_indicators_value_not_empty"),
        # Serves `/indicators?type=` with a stable order: last_seen DESC, id DESC. PostgreSQL
        # can scan this ascending index backwards, so no DESC is needed in the definition.
        Index("ix_indicators_type_last_seen_id", "type", "last_seen", "id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()")
    )
    type: Mapped[IndicatorType] = mapped_column(IndicatorTypeEnum, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    # Feed timestamps when the row carries them, clamped to now() on the way in. Never derived
    # from ingestion time unless the feed has no date at all.
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Latest payload for this indicator, kept so a parser bug can be fixed and reprocessed.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    sources: Mapped[list["IndicatorSource"]] = relationship(
        back_populates="indicator",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class IndicatorSource(Base):
    """Provenance per feed, with its own freshness.

    Rows are upserted when a feed reports the indicator and never deleted implicitly: a
    truncated download must not wipe provenance. "Still reported" is answered by `last_seen`.
    """

    __tablename__ = "indicator_sources"
    __table_args__ = (Index("ix_indicator_sources_feed", "feed"),)

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        primary_key=True,
    )
    feed: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    indicator: Mapped[Indicator] = relationship(back_populates="sources")
