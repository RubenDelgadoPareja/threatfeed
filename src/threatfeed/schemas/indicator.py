"""Indicator payloads returned by `/check` and `/indicators`."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from threatfeed.models import IndicatorType


class IndicatorSourceOut(BaseModel):
    """Provenance of an indicator in one feed, with that feed's own freshness."""

    model_config = ConfigDict(from_attributes=True)

    feed: str
    first_seen: datetime
    last_seen: datetime


class IndicatorOut(BaseModel):
    """An indicator without `raw`: the feed payload stays internal."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: IndicatorType
    value: str
    first_seen: datetime
    last_seen: datetime
    sources: list[IndicatorSourceOut]


class IndicatorPage(BaseModel):
    """One page of indicators plus enough context to request the next one."""

    items: list[IndicatorOut]
    total: int
    limit: int
    offset: int
