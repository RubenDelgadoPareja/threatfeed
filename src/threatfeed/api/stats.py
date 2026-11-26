"""Aggregate counts."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatfeed.api.auth import default_rate_limit
from threatfeed.db.session import get_db
from threatfeed.models import Indicator, IndicatorSource, IndicatorType
from threatfeed.schemas.stats import StatsOut

router = APIRouter(dependencies=[Depends(default_rate_limit)])


@router.get("/stats", response_model=StatsOut)
def get_stats(db: Annotated[Session, Depends(get_db)]) -> StatsOut:
    """Totals per indicator type and per feed."""
    total = db.scalar(select(func.count()).select_from(Indicator)) or 0

    by_type = {member.value: 0 for member in IndicatorType}
    type_counts = db.execute(select(Indicator.type, func.count()).group_by(Indicator.type))
    for indicator_type, count in type_counts:
        by_type[indicator_type.value] = count

    source_counts = db.execute(
        select(IndicatorSource.feed, func.count()).group_by(IndicatorSource.feed)
    )
    by_source = {feed: count for feed, count in source_counts}

    return StatsOut(total=total, by_type=by_type, by_source=by_source)
