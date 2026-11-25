"""URLhaus CSV export ingestor."""

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import quote

from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.dates import parse_utc
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.http import download_lines, redact_url
from threatfeed.models import IndicatorType
from threatfeed.normalize import normalize_url

FEED = "urlhaus"
EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/{export}"
REQUIRED_COLUMNS = {"url", "dateadded"}


def export_url(auth_key: str, export: str) -> str:
    """Build the export URL, percent-encoding the key so it cannot alter the path."""
    return EXPORT_URL.format(key=quote(auth_key, safe=""), export=export)


def parse_indicator(row: dict[str, str | None], now: datetime) -> ParsedIndicator:
    """Normalize one CSV row. Raises `InvalidRow` (or `InvalidUrl`) when unusable."""
    raw_url = (row.get("url") or "").strip()
    if not raw_url:
        raise InvalidRow("missing url")
    value = normalize_url(raw_url)

    first_seen = min(parse_utc(row.get("dateadded") or ""), now)
    last_online_raw = (row.get("last_online") or "").strip()
    last_seen = parse_utc(last_online_raw) if last_online_raw else first_seen
    last_seen = min(max(last_seen, first_seen), now)

    return ParsedIndicator(
        type=IndicatorType.URL,
        value=value,
        first_seen=first_seen,
        last_seen=last_seen,
        raw=dict(row),
    )


class URLHausIngestor(BaseIngestor):
    """Consume one URLhaus CSV export into the indicator store."""

    feed = FEED
    required_columns = REQUIRED_COLUMNS

    def validate(self) -> None:
        if not self.settings.abusech_auth_key:
            raise IngestError(
                "ABUSECH_AUTH_KEY is not configured; get a free key at https://auth.abuse.ch/"
            )

    def describe_source(self) -> str:
        return redact_url(self._export_url())

    @contextmanager
    def open_rows(self) -> Iterator[Iterable[str]]:
        with download_lines(self._export_url()) as lines:
            yield lines

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
        return parse_indicator(row, now)

    def _export_url(self) -> str:
        return export_url(self.settings.abusech_auth_key or "", self.settings.urlhaus_export)
