"""Indicator payloads returned by `/check` and `/indicators`."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, computed_field

from threatfeed.confidence import SourceEvidence, score_confidence
from threatfeed.models import IndicatorType


class IndicatorSourceOut(BaseModel):
    """Provenance of an indicator in one feed, with that feed's own freshness."""

    model_config = ConfigDict(from_attributes=True)

    feed: str
    first_seen: datetime
    last_seen: datetime


class ConfidenceOut(BaseModel):
    score: int
    level: str
    reasons: list[str]


class IndicatorOut(BaseModel):
    """An indicator without `raw`: the feed payload stays internal."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: IndicatorType
    value: str
    first_seen: datetime
    last_seen: datetime
    sources: list[IndicatorSourceOut]

    @computed_field
    @property
    def confidence(self) -> ConfidenceOut:
        evidence = [
            SourceEvidence(feed=source.feed, last_seen=source.last_seen) for source in self.sources
        ]
        result = score_confidence(evidence)
        return ConfidenceOut(score=result.score, level=result.level, reasons=list(result.reasons))


class IndicatorPage(BaseModel):
    """One page of indicators plus enough context to request the next one."""

    items: list[IndicatorOut]
    total: int
    limit: int
    offset: int
