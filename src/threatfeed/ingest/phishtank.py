"""PhishTank online-valid CSV ingestor.

PhishTank is independent of abuse.ch. Its CSV already contains verified and online phishes;
non-compliant rows are treated as malformed so a format regression trips the run guard.
"""

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime

from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.dates import parse_iso8601
from threatfeed.ingest.errors import InvalidRow
from threatfeed.ingest.http import download_lines
from threatfeed.models import IndicatorType
from threatfeed.normalize import normalize_url

FEED = "phishtank"
EXPORT_URL = "https://data.phishtank.com/data/online-valid.csv"
REQUIRED_COLUMNS = {
    "url",
    "submission_time",
    "verification_time",
    "verified",
    "online",
}


def parse_indicator(row: dict[str, str | None], now: datetime) -> ParsedIndicator:
    if (row.get("verified") or "").strip().lower() != "yes":
        raise InvalidRow("phish is not verified")
    if (row.get("online") or "").strip().lower() != "yes":
        raise InvalidRow("phish is not online")

    raw_url = (row.get("url") or "").strip()
    if not raw_url:
        raise InvalidRow("missing url")
    value = normalize_url(raw_url)

    first_seen = min(parse_iso8601(row.get("submission_time") or ""), now)
    verification = (row.get("verification_time") or "").strip()
    last_seen = parse_iso8601(verification) if verification else first_seen
    last_seen = min(max(last_seen, first_seen), now)

    return ParsedIndicator(
        type=IndicatorType.URL,
        value=value,
        first_seen=first_seen,
        last_seen=last_seen,
        raw=dict(row),
    )


class PhishTankIngestor(BaseIngestor):
    """Consume PhishTank's verified, online phishing URLs."""

    feed = FEED
    required_columns = REQUIRED_COLUMNS

    def describe_source(self) -> str:
        return EXPORT_URL

    @contextmanager
    def open_rows(self) -> Iterator[Iterable[str]]:
        with download_lines(EXPORT_URL) as lines:
            yield lines

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
        return parse_indicator(row, now)
