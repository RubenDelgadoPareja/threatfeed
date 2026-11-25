from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from threatfeed.ingest.csv import iter_rows
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.http import redact_url
from threatfeed.ingest.urlhaus import REQUIRED_COLUMNS, export_url, parse_indicator
from threatfeed.normalize import InvalidUrl

FIXTURE = Path(__file__).parent / "fixtures" / "urlhaus_recent.csv"
NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def _rows() -> list[dict[str, str | None]]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return list(iter_rows(stream, REQUIRED_COLUMNS))


def test_iter_rows_skips_comments_and_blank_lines() -> None:
    assert len(_rows()) == 5


def test_iter_rows_accepts_an_uncommented_header() -> None:
    text = '"url","dateadded"\n"http://example.com","2026-01-01"\n'

    assert list(iter_rows(StringIO(text), REQUIRED_COLUMNS)) == [
        {"url": "http://example.com", "dateadded": "2026-01-01"}
    ]


def test_iter_rows_accepts_a_comment_prefixed_header() -> None:
    text = (
        "################################################################\n"
        "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-01-01 00:00:00","http://example.com","online","","malware_download","exe","","abuse_ch"\n'
    )

    rows = list(iter_rows(StringIO(text), REQUIRED_COLUMNS))

    assert rows == [
        {
            "id": "1",
            "dateadded": "2026-01-01 00:00:00",
            "url": "http://example.com",
            "url_status": "online",
            "last_online": "",
            "threat": "malware_download",
            "tags": "exe",
            "urlhaus_link": "",
            "reporter": "abuse_ch",
        }
    ]


def test_iter_rows_accepts_a_bom() -> None:
    text = '\ufeff# comment\n"url","dateadded"\n"http://example.com","2026-01-01"\n'

    assert list(iter_rows(StringIO(text), REQUIRED_COLUMNS)) == [
        {"url": "http://example.com", "dateadded": "2026-01-01"}
    ]


def test_iter_rows_requires_url_and_dateadded() -> None:
    text = '"url","date" \n"http://example.com","2026-01-01"\n'

    with pytest.raises(IngestError, match="dateadded"):
        list(iter_rows(StringIO(text), REQUIRED_COLUMNS))


@pytest.mark.parametrize("text", ["", "# only a comment\n", "\n\n"])
def test_iter_rows_rejects_an_empty_feed(text: str) -> None:
    with pytest.raises(IngestError, match="empty"):
        list(iter_rows(StringIO(text), REQUIRED_COLUMNS))


def test_parse_row_normalizes_the_url_and_keeps_the_original_payload() -> None:
    parsed = parse_indicator(_rows()[0], NOW)

    assert parsed.value == "http://example.com/a?b=1"
    assert parsed.first_seen == datetime(2026, 3, 1, 10, 0, tzinfo=UTC)
    assert parsed.last_seen == datetime(2026, 3, 2, tzinfo=UTC)
    assert parsed.raw["url"] == "HTTP://Example.COM:80/a?b=1#frag"


def test_parse_row_uses_dateadded_when_last_online_is_empty() -> None:
    parsed = parse_indicator(_rows()[1], NOW)

    assert parsed.first_seen == parsed.last_seen


def test_parse_row_keeps_quoted_fields_intact() -> None:
    parsed = parse_indicator(_rows()[3], NOW)

    assert parsed.value == "https://quoted.test/a,b?c=d"
    assert parsed.raw["tags"] == "tag with space,exe"


def test_parse_row_clamps_future_dates_to_now() -> None:
    parsed = parse_indicator(_rows()[0], datetime(2026, 1, 1, tzinfo=UTC))

    assert parsed.first_seen == parsed.last_seen == datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_row_rejects_an_unsupported_scheme() -> None:
    with pytest.raises(InvalidUrl):
        parse_indicator(_rows()[2], NOW)


def test_parse_row_rejects_a_missing_dateadded() -> None:
    with pytest.raises(InvalidRow, match="timestamp"):
        parse_indicator(_rows()[4], NOW)


def test_redact_url_hides_the_auth_key() -> None:
    url = "https://urlhaus-api.abuse.ch/v2/files/exports/s3cr3t/recent.csv"

    redacted = redact_url(url)

    assert "s3cr3t" not in redacted
    assert redacted == "https://urlhaus-api.abuse.ch/v2/files/exports/***/recent.csv"


def test_export_url_quotes_the_key_so_it_cannot_alter_the_path() -> None:
    url = export_url("a/b?c", "recent.csv")

    assert url == "https://urlhaus-api.abuse.ch/v2/files/exports/a%2Fb%3Fc/recent.csv"
