"""Totals exposed by `/stats`."""

from pydantic import BaseModel


class StatsOut(BaseModel):
    total: int
    # Every indicator type is present, including zeros, so the contract is stable.
    by_type: dict[str, int]
    by_source: dict[str, int]
