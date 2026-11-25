from datetime import UTC, datetime
from pathlib import Path

import pytest

from threatfeed.ingest.csv import iter_rows
from threatfeed.ingest.errors import InvalidRow
from threatfeed.ingest.http import redact_url
from threatfeed.ingest.threatfox import (
    REQUIRED_COLUMNS,
    export_url,
    parse_indicator,
)
from threatfeed.models import IndicatorType

FIXTURE = Path(__file__).parent / "fixtures" / "threatfox_full.csv"
NOW = datetime(2026, 11, 26, 0, 0, tzinfo=UTC)


def _rows() -> list[dict[str, str | None]]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return list(iter_rows(stream, REQUIRED_COLUMNS))


def test_iter_rows_handles_the_real_dialect() -> None:
    rows = _rows()

    assert len(rows) == 11
    assert rows[0]["ioc_type"] == "domain"
    assert rows[0]["ioc_value"] == "metal-industrial.com"
    assert rows[0]["tags"] == "ClickFix,etherhiding"


def test_parse_domain() -> None:
    parsed = parse_indicator(_rows()[0], NOW)

    assert parsed is not None
    assert parsed.type is IndicatorType.DOMAIN
    assert parsed.value == "metal-industrial.com"
    assert parsed.first_seen == datetime(2026, 11, 25, 18, 32, 44, tzinfo=UTC)
    assert parsed.last_seen == parsed.first_seen


def test_parse_ip_port_strips_the_port_and_keeps_it_in_raw() -> None:
    parsed = parse_indicator(_rows()[1], NOW)

    assert parsed is not None
    assert parsed.type is IndicatorType.IP
    assert parsed.value == "2.27.209.43"
    assert parsed.raw["ioc_value"] == "2.27.209.43:5501"


def test_parse_url_uses_the_shared_canonicalizer() -> None:
    parsed = parse_indicator(_rows()[2], NOW)

    assert parsed is not None
    assert parsed.type is IndicatorType.URL
    assert parsed.value == "http://176.194.109.14:65177/bin.sh"


def test_parse_hashes_lowercases_them() -> None:
    parsed = parse_indicator(_rows()[3], NOW)
    assert parsed is not None
    assert parsed.type is IndicatorType.HASH_MD5
    assert parsed.value == "f726ea9572f9737f350784e7e14369e7"

    parsed = parse_indicator(_rows()[4], NOW)
    assert parsed is not None
    assert parsed.type is IndicatorType.HASH_SHA256


def test_sha1_is_skipped() -> None:
    assert parse_indicator(_rows()[5], NOW) is None


def test_empty_last_seen_falls_back_to_first_seen() -> None:
    parsed = parse_indicator(_rows()[1], NOW)

    assert parsed is not None
    assert parsed.last_seen == parsed.first_seen


def test_future_last_seen_is_clamped_to_now() -> None:
    parsed = parse_indicator(_rows()[6], NOW)

    assert parsed is not None
    assert parsed.last_seen == NOW


def test_malformed_ip_port_is_rejected() -> None:
    with pytest.raises(InvalidRow, match="IP"):
        parse_indicator(_rows()[7], NOW)


def test_type_mismatch_is_rejected() -> None:
    with pytest.raises(InvalidRow, match="domain"):
        parse_indicator(_rows()[8], NOW)


def test_unknown_ioc_type_is_rejected() -> None:
    with pytest.raises(InvalidRow, match="unsupported ioc_type"):
        parse_indicator(_rows()[9], NOW)


def test_same_ip_on_two_ports_maps_to_the_same_indicator() -> None:
    first = parse_indicator(_rows()[1], NOW)
    second = parse_indicator(_rows()[10], NOW)

    assert first is not None and second is not None
    assert first.type is second.type
    assert first.value == second.value == "2.27.209.43"


def test_redact_url_hides_the_auth_key() -> None:
    url = "https://threatfox-api.abuse.ch/v2/files/exports/s3cr3t/full.csv.zip"

    redacted = redact_url(url)

    assert "s3cr3t" not in redacted
    assert redacted == "https://threatfox-api.abuse.ch/v2/files/exports/***/full.csv.zip"


def test_export_url_quotes_the_key() -> None:
    url = export_url("a/b")

    assert url == "https://threatfox-api.abuse.ch/v2/files/exports/a%2Fb/full.csv.zip"


def test_parse_preserves_the_whole_payload_in_raw() -> None:
    parsed = parse_indicator(_rows()[0], NOW)

    assert parsed is not None
    assert sorted(parsed.raw) == sorted(_rows()[0])
    assert parsed.raw["malware_printable"] == "IClickFix"
