from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from threatfeed.ingest.csv import iter_rows
from threatfeed.ingest.errors import IngestError, InvalidRow
from threatfeed.ingest.phishtank import REQUIRED_COLUMNS, parse_indicator
from threatfeed.models import IndicatorType
from threatfeed.normalize import InvalidUrl

FIXTURE = Path(__file__).parent / "fixtures" / "phishtank_online_valid.csv"
NOW = datetime(2026, 11, 26, tzinfo=UTC)


def _rows() -> list[dict[str, str | None]]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return list(iter_rows(stream, REQUIRED_COLUMNS))


def test_iter_rows_reads_the_plain_header() -> None:
    rows = _rows()

    assert len(rows) == 6
    assert rows[0]["url"] == "https://phish.example/login"
    assert rows[0]["target"] == "Example"


def test_parse_maps_submission_and_verification() -> None:
    parsed = parse_indicator(_rows()[0], NOW)

    assert parsed.type is IndicatorType.URL
    assert parsed.value == "https://phish.example/login"
    assert parsed.first_seen == datetime(2026, 11, 25, 21, 54, 7, tzinfo=UTC)
    assert parsed.last_seen == datetime(2026, 11, 25, 22, 2, 8, tzinfo=UTC)


def test_parse_normalizes_the_url() -> None:
    parsed = parse_indicator(_rows()[1], NOW)

    assert parsed.value == "http://phish.example/a"


def test_missing_verification_falls_back_to_submission() -> None:
    parsed = parse_indicator(_rows()[4], NOW)

    assert parsed.first_seen == parsed.last_seen


def test_future_dates_are_clamped() -> None:
    parsed = parse_indicator(_rows()[0], datetime(2026, 1, 1, tzinfo=UTC))

    assert parsed.first_seen == parsed.last_seen == datetime(2026, 1, 1, tzinfo=UTC)


def test_unverified_rows_are_rejected() -> None:
    with pytest.raises(InvalidRow, match="not verified"):
        parse_indicator(_rows()[2], NOW)


def test_invalid_urls_are_rejected() -> None:
    with pytest.raises(InvalidUrl):
        parse_indicator(_rows()[3], NOW)


def test_duplicate_urls_parse_to_the_same_value() -> None:
    first = parse_indicator(_rows()[0], NOW)
    duplicate = parse_indicator(_rows()[5], NOW)

    assert first.type is duplicate.type
    assert first.value == duplicate.value


def test_missing_columns_fail_before_parsing() -> None:
    text = (
        "phish_id,url,submission_time,verified,verification_time\n"
        "1,https://phish.example,2026-11-25T21:54:07+00:00,yes,2026-11-25T22:00:00+00:00\n"
    )

    with pytest.raises(IngestError, match="online"):
        list(iter_rows(StringIO(text), REQUIRED_COLUMNS))
