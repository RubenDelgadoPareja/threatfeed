from pathlib import Path

from threatfeed.logs import Observable, parse_line
from threatfeed.models import IndicatorType

FIXTURE = Path(__file__).parent / "fixtures" / "nginx_access.log"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_relative_request_only_yields_the_client_ip() -> None:
    assert parse_line(_lines()[0]) == [
        Observable(type=IndicatorType.IP, value="1.2.3.4", field="remote_addr")
    ]


def test_absolute_urls_in_request_and_referer_are_extracted() -> None:
    assert parse_line(_lines()[1]) == [
        Observable(type=IndicatorType.IP, value="5.6.7.8", field="remote_addr"),
        Observable(type=IndicatorType.URL, value="http://bad.example/payload", field="request"),
        Observable(type=IndicatorType.URL, value="http://evil.example/ref", field="referer"),
    ]


def test_unparseable_line_returns_none() -> None:
    assert parse_line(_lines()[2]) is None


def test_referer_is_normalized() -> None:
    line = (
        '1.2.3.4 - - [25/Nov/2026:10:00:00 +0000] "GET /x HTTP/1.1" 200 1 '
        '"HTTP://Evil.Example:80/ref#frag" "-"'
    )

    observables = parse_line(line)

    assert observables is not None
    assert observables[1] == Observable(
        type=IndicatorType.URL, value="http://evil.example/ref", field="referer"
    )


def test_invalid_remote_addr_does_not_hide_the_urls() -> None:
    line = (
        'not-an-ip - - [25/Nov/2026:10:00:00 +0000] "GET http://bad.example/x HTTP/1.1" '
        '200 1 "-" "-"'
    )

    observables = parse_line(line)

    assert observables == [
        Observable(type=IndicatorType.URL, value="http://bad.example/x", field="request")
    ]
