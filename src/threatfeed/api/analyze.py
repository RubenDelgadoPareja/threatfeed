"""Match an nginx access log against the indicator store, without loading it into memory."""

import uuid
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session, selectinload

from threatfeed.db.session import get_db
from threatfeed.logs import Observable, parse_line
from threatfeed.models import Indicator
from threatfeed.schemas.logs import LogAnalysisOut, LogMatch

router = APIRouter()

MAX_LOG_BYTES = 10 * 1024 * 1024
MAX_MATCHES_DEFAULT = 100
MAX_MATCHES_LIMIT = 1_000
CHUNK_LINES = 500


@dataclass
class _Accumulator:
    indicator: Indicator
    hits: int = 0
    first_line: int = 0
    last_line: int = 0
    matched_on: set[str] = field(default_factory=set)


@router.post("/analyze/logs", response_model=LogAnalysisOut)
def analyze_logs(
    db: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile, File(...)],
    max_matches: Annotated[int, Query(ge=1, le=MAX_MATCHES_LIMIT)] = MAX_MATCHES_DEFAULT,
) -> LogAnalysisOut:
    """Stream a combined log, look up its observables in batches and summarize the matches."""
    found: dict[uuid.UUID, _Accumulator] = {}
    chunk: list[tuple[int, list[Observable]]] = []
    lines_read = 0
    lines_skipped = 0
    total_bytes = 0

    for raw in file.file:
        total_bytes += len(raw)
        if total_bytes > MAX_LOG_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"log exceeds the {MAX_LOG_BYTES} byte limit; split it into smaller files",
            )

        lines_read += 1
        observables = parse_line(raw.decode("utf-8", errors="replace"))
        if observables is None:
            lines_skipped += 1
            continue

        chunk.append((lines_read, observables))
        if len(chunk) >= CHUNK_LINES:
            _match_chunk(db, chunk, found)
            chunk.clear()

    if chunk:
        _match_chunk(db, chunk, found)

    ordered = sorted(
        found.values(), key=lambda item: (item.first_line, item.last_line, item.indicator.value)
    )
    return LogAnalysisOut(
        lines_read=lines_read,
        lines_skipped=lines_skipped,
        unique_indicators=len(ordered),
        truncated=len(ordered) > max_matches,
        matches=[_to_match(item) for item in ordered[:max_matches]],
    )


def _match_chunk(
    db: Session, chunk: list[tuple[int, list[Observable]]], found: dict[uuid.UUID, _Accumulator]
) -> None:
    pairs = {
        (observable.type, observable.value)
        for _, observables in chunk
        for observable in observables
    }
    if not pairs:
        return

    rows = db.scalars(
        select(Indicator)
        .options(selectinload(Indicator.sources), selectinload(Indicator.geo))
        .where(tuple_(Indicator.type, Indicator.value).in_(list(pairs)))
    ).all()
    by_key = {(indicator.type, indicator.value): indicator for indicator in rows}

    for line_number, observables in chunk:
        seen_on_line: set[uuid.UUID] = set()
        for observable in observables:
            indicator = by_key.get((observable.type, observable.value))
            if indicator is None:
                continue

            accumulator = found.get(indicator.id)
            if accumulator is None:
                accumulator = _Accumulator(
                    indicator=indicator, first_line=line_number, last_line=line_number
                )
                found[indicator.id] = accumulator

            accumulator.matched_on.add(observable.field)
            if indicator.id in seen_on_line:
                continue
            seen_on_line.add(indicator.id)
            accumulator.hits += 1
            accumulator.last_line = line_number


def _to_match(accumulator: _Accumulator) -> LogMatch:
    return LogMatch(
        indicator=accumulator.indicator,
        hits=accumulator.hits,
        first_line=accumulator.first_line,
        last_line=accumulator.last_line,
        matched_on=sorted(accumulator.matched_on),
    )
