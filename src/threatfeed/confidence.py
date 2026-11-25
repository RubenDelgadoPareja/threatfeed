"""Explainable confidence for an indicator: how many feeds agree and how fresh they are."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

FRESH_DAYS = 7
RECENT_DAYS = 30
FRESH_BONUS = 10
RECENT_BONUS = 5
HIGH_THRESHOLD = 80
MEDIUM_THRESHOLD = 50
MANY_SOURCES_SCORE = 90


@dataclass(frozen=True)
class SourceEvidence:
    """The minimum a source needs to contribute to the score."""

    feed: str
    last_seen: datetime


@dataclass(frozen=True)
class Confidence:
    score: int
    level: str
    reasons: tuple[str, ...]


def score_confidence(
    sources: Iterable[SourceEvidence], *, now: datetime | None = None
) -> Confidence:
    """Score 0-100 from distinct feeds plus the freshness of the latest report.

    Counting feeds, not providers, is a deliberate v1 choice: both current feeds are abuse.ch,
    so cross-provider weighting waits until a third, independent provider exists.
    """
    evidence = list(sources)
    current = now or datetime.now(UTC)
    distinct_feeds = {source.feed for source in evidence}
    count = len(distinct_feeds)

    if count == 0:
        return Confidence(score=0, level="low", reasons=("no sources",))

    base = {1: 40, 2: 70}.get(count, MANY_SOURCES_SCORE)
    reasons = ["1 source" if count == 1 else f"{count} sources agree"]

    latest = max(source.last_seen for source in evidence)
    age_days = max(0, (current - latest).days)
    if age_days <= FRESH_DAYS:
        bonus = FRESH_BONUS
        reasons.append(_freshness_reason(age_days))
    elif age_days <= RECENT_DAYS:
        bonus = RECENT_BONUS
        reasons.append(_freshness_reason(age_days))
    else:
        bonus = 0
        reasons.append(f"stale: last seen {age_days} days ago")

    score = min(100, base + bonus)
    return Confidence(score=score, level=_level(score), reasons=tuple(reasons))


def _freshness_reason(age_days: int) -> str:
    if age_days == 0:
        return "seen today"
    if age_days == 1:
        return "seen yesterday"
    return f"seen {age_days} days ago"


def _level(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"
