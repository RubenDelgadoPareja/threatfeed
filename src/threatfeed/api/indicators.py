"""Lookup and listing endpoints.

Plain `def` endpoints run in FastAPI's threadpool, so the synchronous SQLAlchemy session never
blocks the event loop. `get_db` opens one session per request and always closes it.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from threatfeed.classification import MAX_VALUE_LENGTH, InvalidIndicator, classify_indicator
from threatfeed.db.session import get_db
from threatfeed.models import Indicator, IndicatorType
from threatfeed.schemas.indicator import IndicatorOut, IndicatorPage

router = APIRouter()


@router.get(
    "/check",
    response_model=IndicatorOut,
    responses={404: {"description": "Indicator not found"}},
)
def check_indicator(
    value: Annotated[str, Query(min_length=1, max_length=MAX_VALUE_LENGTH)],
    db: Annotated[Session, Depends(get_db)],
) -> Indicator:
    """Is this IP, domain, URL or hash known? Returns type, provenance and dates."""
    try:
        indicator_type, normalized = classify_indicator(value)
    except InvalidIndicator as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    indicator = db.scalar(
        select(Indicator)
        .options(selectinload(Indicator.sources))
        .where(Indicator.type == indicator_type, Indicator.value == normalized)
    )
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")

    return indicator


@router.get("/indicators", response_model=IndicatorPage)
def list_indicators(
    db: Annotated[Session, Depends(get_db)],
    indicator_type: Annotated[IndicatorType | None, Query(alias="type")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IndicatorPage:
    """Paginated listing, newest first, optionally filtered by type."""
    filters = [] if indicator_type is None else [Indicator.type == indicator_type]

    total = db.scalar(select(func.count()).select_from(Indicator).where(*filters)) or 0
    items = db.scalars(
        select(Indicator)
        .options(selectinload(Indicator.sources))
        .where(*filters)
        .order_by(Indicator.last_seen.desc(), Indicator.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    return IndicatorPage(items=list(items), total=total, limit=limit, offset=offset)
