"""ThreatFox full CSV export ingestor.

The export is a ZIP whose CSV can be large (35 MB, ~150k IOCs). Unsupported IOC types such as
`sha1_hash` are counted as skipped rows; the model's vocabulary stays closed.
"""

import io
import ipaddress
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from threatfeed.classification import InvalidIndicator, classify_indicator
from threatfeed.ingest.base import BaseIngestor, ParsedIndicator
from threatfeed.ingest.dates import parse_utc
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.http import download_zip, redact_url
from threatfeed.models import IndicatorType

FEED = "threatfox"
EXPORT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{key}/{export}"
EXPORT_NAME = "full.csv.zip"
CACHE_PATH = Path(".cache") / "threatfeed" / "threatfox-full.csv.zip"
REQUIRED_COLUMNS = {"first_seen_utc", "ioc_value", "ioc_type"}

# The feed declares the type; classification must agree with it.
EXPECTED_TYPES = {
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.HASH_MD5,
    "sha256_hash": IndicatorType.HASH_SHA256,
}


def export_url(auth_key: str) -> str:
    """Build the export URL, percent-encoding the key so it cannot alter the path."""
    return EXPORT_URL.format(key=quote(auth_key, safe=""), export=quote(EXPORT_NAME, safe=""))


def parse_indicator(row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
    """Map one ThreatFox row. Returns None for IOC types the model does not store."""
    ioc_type = (row.get("ioc_type") or "").strip().lower()
    if ioc_type == "sha1_hash":
        return None

    raw_value = (row.get("ioc_value") or "").strip()
    if not raw_value:
        raise InvalidRow("missing ioc_value")

    first_seen = min(parse_utc(row.get("first_seen_utc") or ""), now)
    last_seen_raw = (row.get("last_seen_utc") or "").strip()
    last_seen = parse_utc(last_seen_raw) if last_seen_raw else first_seen
    last_seen = min(max(last_seen, first_seen), now)

    if ioc_type == "ip:port":
        value = _normalize_ip_port(raw_value)
        indicator_type = IndicatorType.IP
    else:
        expected = EXPECTED_TYPES.get(ioc_type)
        if expected is None:
            raise InvalidRow(f"unsupported ioc_type: {ioc_type!r}")
        try:
            indicator_type, value = classify_indicator(raw_value)
        except InvalidIndicator as exc:
            raise InvalidRow(str(exc)) from exc
        if indicator_type is not expected:
            raise InvalidRow(f"{ioc_type} row contains a {indicator_type.value}")

    return ParsedIndicator(
        type=indicator_type,
        value=value,
        first_seen=first_seen,
        last_seen=last_seen,
        raw=dict(row),
    )


def _normalize_ip_port(value: str) -> str:
    """`1.2.3.4:443` and `[2001:db8::1]:443` become the bare IP; the port stays in `raw`."""
    host = value
    port = ""

    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise InvalidRow(f"unbracketed IPv6 address: {value!r}")
        host = value[1:end]
        port = value[end + 1 :].lstrip(":")
    elif value.count(":") == 1:
        host, port = value.split(":", 1)

    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise InvalidRow(f"invalid port in {value!r}")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError as exc:
        raise InvalidRow(f"invalid IP address: {value!r}") from exc


class ThreatFoxIngestor(BaseIngestor):
    """Consume the full ThreatFox CSV export (a ZIP) into the indicator store."""

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
        with (
            download_zip(self._export_url(), CACHE_PATH) as path,
            zipfile.ZipFile(path) as archive,
        ):
            members = [name for name in archive.namelist() if name.endswith(".csv")]
            if not members:
                raise IngestError("export ZIP contains no CSV file")
            with (
                archive.open(members[0]) as raw,
                io.TextIOWrapper(raw, encoding="utf-8-sig") as text,
            ):
                yield text

    def parse_row(self, row: dict[str, str | None], now: datetime) -> ParsedIndicator | None:
        return parse_indicator(row, now)

    def _export_url(self) -> str:
        return export_url(self.settings.abusech_auth_key or "")
