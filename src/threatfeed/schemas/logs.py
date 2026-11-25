"""Response payloads for `/analyze/logs`."""

from pydantic import BaseModel

from threatfeed.schemas.indicator import IndicatorOut


class LogMatch(BaseModel):
    indicator: IndicatorOut
    hits: int
    first_line: int
    last_line: int
    matched_on: list[str]


class LogAnalysisOut(BaseModel):
    lines_read: int
    lines_skipped: int
    unique_indicators: int
    truncated: bool
    matches: list[LogMatch]
